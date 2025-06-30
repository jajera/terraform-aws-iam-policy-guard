"""
IAM Policy Analytics Engine
Automatically creates Athena infrastructure and analytics capabilities for IAM violations.
Provides automated insights, trend analysis, and proactive security intelligence.
"""

import json
import os
import time
from typing import Any

import boto3

# Initialize AWS clients
athena_client = boto3.client("athena")
glue_client = boto3.client("glue")
cloudwatch_client = boto3.client("cloudwatch")

# Environment variables
DATABASE_NAME = os.environ["ATHENA_DATABASE_NAME"]
RESULTS_BUCKET = os.environ["ATHENA_RESULTS_BUCKET"]
TABLE_LOCATION = os.environ["TABLE_LOCATION"]
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Main Lambda handler for Athena table creation and analytics.

    Actions:
    - create_table: Initialize database with violations table and analytics views
    - run_analytics: Execute security analytics queries and publish metrics
    - cleanup_database: Drop all tables/views before database deletion (force destroy)
    """
    try:
        action = event.get("action", "create_table")

        if action == "create_table":
            return handle_table_creation(event, context)
        elif action == "run_analytics":
            return handle_analytics_execution(event, context)
        elif action == "cleanup_database":
            database_name = event.get("database_name", DATABASE_NAME)
            return handle_database_cleanup(database_name)
        else:
            raise ValueError(f"Unknown action: {action}")

    except Exception as e:
        print(f"❌ Lambda execution failed: {e!s}")
        print(f"Event: {json.dumps(event, default=str)}")
        raise


def handle_table_creation(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Analytics Engine handler - creates table and automated analytics infrastructure.
    """
    try:
        print("🚀 Initializing IAM Policy Analytics Engine")
        print(f"Database: {DATABASE_NAME}")
        print(f"Data location: {TABLE_LOCATION}")

        # Step 1: Create the violations table
        table_created = create_violations_table(
            DATABASE_NAME, RESULTS_BUCKET, TABLE_LOCATION
        )

        # Step 2: Create analytics views and saved queries
        analytics_setup = setup_analytics_infrastructure(DATABASE_NAME, RESULTS_BUCKET)

        # Step 3: Set up automated metrics and insights
        metrics_setup = setup_automated_metrics(DATABASE_NAME, RESULTS_BUCKET)

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Analytics engine initialized successfully",
                    "components": {
                        "violations_table": table_created,
                        "analytics_views": analytics_setup,
                        "automated_metrics": metrics_setup,
                    },
                }
            ),
        }

    except Exception as e:
        print(f"❌ Error in analytics engine: {e!s}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e), "component": "analytics_engine"}),
        }


def create_violations_table(
    database_name: str, results_bucket: str, table_location: str
) -> dict[str, Any]:
    """Create the main violations table."""
    print("📊 Creating violations table...")

    # Check if table already exists
    try:
        glue_client.get_table(DatabaseName=database_name, Name="violations")
        print("✅ Table 'violations' already exists")
        return {"status": "exists", "action": "skipped"}
    except glue_client.exceptions.EntityNotFoundException:
        print("🔨 Creating new violations table...")

    create_table_sql = f"""
    CREATE EXTERNAL TABLE IF NOT EXISTS {database_name}.violations (
      `timestamp` string,
      event_name string,
      event_source string,
      aws_region string,
      source_ip_address string,
      user_agent string,
      user_identity struct<
        `type`: string,
        principalId: string,
        arn: string,
        accountId: string,
        userName: string
      >,
      resources array<struct<
        accountId: string,
        `type`: string,
        ARN: string
      >>,
      rule_name string,
      severity string,
      action_taken string,
      remediation_action string,
      suppressed boolean,
      violation_details struct<
        policy_name: string,
        policy_arn: string,
        attached_to: string
      >
    )
    PARTITIONED BY (
      `year` string,
      `month` string,
      `day` string
    )
    ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
    WITH SERDEPROPERTIES ('serialization.format' = '1')
    STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION '{table_location}'
    """

    query_id = execute_athena_query(
        create_table_sql,
        database_name,
        results_bucket,
        "Creating violations table",
    )
    return {"status": "created", "query_id": query_id}


def setup_analytics_infrastructure(
    database_name: str, results_bucket: str
) -> dict[str, Any]:
    """Set up analytics views and automated insights."""
    print("🔍 Setting up analytics infrastructure...")

    analytics_queries = [
        {
            "name": "violation_trends_view",
            "description": "Daily violation trends and patterns",
            "sql": f"""
            CREATE OR REPLACE VIEW {database_name}.violation_trends AS
            SELECT
                date_parse(timestamp, '%Y-%m-%d') as violation_date,
                severity,
                rule_name,
                COUNT(*) as violation_count,
                COUNT(DISTINCT user_identity.arn) as unique_principals,
                COUNT(DISTINCT violation_details.policy_name) as unique_policies
            FROM {database_name}.violations
            WHERE timestamp >= date_format(date_add('day', -30, now()), '%Y-%m-%d')
            GROUP BY date_parse(timestamp, '%Y-%m-%d'), severity, rule_name
            ORDER BY violation_date DESC, violation_count DESC
            """,
        },
        {
            "name": "high_risk_principals_view",
            "description": "Principals with multiple violations (potential compromise indicators)",
            "sql": f"""
            CREATE OR REPLACE VIEW {database_name}.high_risk_principals AS
            SELECT
                user_identity.arn as principal_arn,
                user_identity.type as principal_type,
                COUNT(*) as total_violations,
                COUNT(DISTINCT rule_name) as unique_rule_violations,
                MAX(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as has_critical_violations,
                array_agg(DISTINCT rule_name) as violated_rules,
                MAX(timestamp) as latest_violation,
                COUNT(CASE WHEN suppressed = false THEN 1 END) as unsuppressed_violations
            FROM {database_name}.violations
            WHERE timestamp >= date_format(date_add('day', -7, now()), '%Y-%m-%d')
            GROUP BY user_identity.arn, user_identity.type
            HAVING COUNT(*) > 3 OR COUNT(DISTINCT rule_name) > 2
            ORDER BY total_violations DESC, unique_rule_violations DESC
            """,
        },
        {
            "name": "policy_attack_patterns_view",
            "description": "Detect potential policy manipulation attacks",
            "sql": f"""
            CREATE OR REPLACE VIEW {database_name}.policy_attack_patterns AS
            SELECT
                violation_details.policy_name,
                violation_details.attached_to,
                COUNT(*) as modification_count,
                COUNT(DISTINCT user_identity.arn) as unique_actors,
                COUNT(DISTINCT source_ip_address) as unique_source_ips,
                array_agg(DISTINCT user_identity.arn) as actors,
                array_agg(DISTINCT source_ip_address) as source_ips,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM {database_name}.violations
            WHERE timestamp >= date_format(date_add('day', -24, now()), '%Y-%m-%d')
                AND rule_name IN ('DangerousInlinePolicy', 'AdminPolicyAttachment', 'PolicyModification')
            GROUP BY violation_details.policy_name, violation_details.attached_to
            HAVING COUNT(*) > 5 OR COUNT(DISTINCT source_ip_address) > 2
            ORDER BY modification_count DESC
            """,
        },
    ]

    created_views = []
    for query_config in analytics_queries:
        try:
            query_id = execute_athena_query(
                query_config["sql"],
                database_name,
                results_bucket,
                f"Creating {query_config['name']}",
            )
            created_views.append(
                {
                    "name": query_config["name"],
                    "description": query_config["description"],
                    "query_id": query_id,
                    "status": "created",
                }
            )
        except Exception as e:
            print(f"⚠️ Failed to create {query_config['name']}: {e!s}")
            created_views.append(
                {
                    "name": query_config["name"],
                    "status": "failed",
                    "error": str(e),
                }
            )

    return {"views": created_views}


def setup_automated_metrics(database_name: str, results_bucket: str) -> dict[str, Any]:
    """Set up automated metrics collection and alerting."""
    print("📈 Setting up automated metrics...")

    # Create a Lambda function (via CloudWatch Events) that runs analytics queries periodically
    # and publishes custom metrics to CloudWatch

    metrics_queries = [
        {
            "name": "daily_violation_summary",
            "metric_name": "ViolationTrends",
            "sql": f"""
            SELECT
                severity,
                COUNT(*) as count
            FROM {database_name}.violations
            WHERE timestamp >= date_format(date_add('day', -1, now()), '%Y-%m-%d')
            GROUP BY severity
            """,
        },
        {
            "name": "high_risk_principals_count",
            "metric_name": "HighRiskPrincipals",
            "sql": f"""
            SELECT COUNT(*) as high_risk_count
            FROM {database_name}.high_risk_principals
            """,
        },
        {
            "name": "potential_attacks_count",
            "metric_name": "PotentialAttacks",
            "sql": f"""
            SELECT COUNT(*) as attack_patterns
            FROM {database_name}.policy_attack_patterns
            """,
        },
    ]

    # Execute metrics queries and publish to CloudWatch
    metrics_results = []
    for metric_config in metrics_queries:
        try:
            query_id = execute_athena_query(
                metric_config["sql"],
                database_name,
                results_bucket,
                f"Collecting {metric_config['name']} metrics",
            )

            # Get query results and publish to CloudWatch
            results = get_query_results(query_id)
            publish_metrics_to_cloudwatch(metric_config["metric_name"], results)

            metrics_results.append(
                {
                    "name": metric_config["name"],
                    "metric_name": metric_config["metric_name"],
                    "query_id": query_id,
                    "status": "published",
                }
            )
        except Exception as e:
            print(f"⚠️ Failed to collect {metric_config['name']}: {e!s}")
            metrics_results.append(
                {
                    "name": metric_config["name"],
                    "status": "failed",
                    "error": str(e),
                }
            )

    return {"metrics": metrics_results}


def execute_athena_query(
    sql: str, database: str, results_bucket: str, description: str
) -> str:
    """Execute an Athena query and wait for completion."""
    print(f"🔄 {description}...")

    response = athena_client.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": f"s3://{results_bucket}/"},
    )

    query_id = response["QueryExecutionId"]

    # Wait for completion
    max_attempts = 30
    for attempt in range(max_attempts):
        status_response = athena_client.get_query_execution(QueryExecutionId=query_id)
        status = status_response["QueryExecution"]["Status"]["State"]

        if status == "SUCCEEDED":
            print(f"✅ {description} completed successfully")
            return query_id
        elif status == "FAILED":
            error = status_response["QueryExecution"]["Status"].get(
                "StateChangeReason", "Unknown error"
            )
            raise Exception(f"{description} failed: {error}")
        elif status == "CANCELLED":
            raise Exception(f"{description} was cancelled")

        time.sleep(2)

    raise Exception(f"{description} timed out")


def get_query_results(query_id: str) -> list[dict]:
    """Get results from an Athena query."""
    try:
        response = athena_client.get_query_results(QueryExecutionId=query_id)

        # Extract column names
        columns = [
            col["Label"]
            for col in response["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
        ]

        # Extract data rows (skip header row)
        rows = []
        for row_data in response["ResultSet"]["Rows"][1:]:  # Skip header
            row = {}
            for i, col in enumerate(columns):
                value = row_data["Data"][i].get("VarCharValue", "")
                row[col] = value
            rows.append(row)

        return rows
    except Exception as e:
        print(f"⚠️ Failed to get query results: {e!s}")
        return []


def publish_metrics_to_cloudwatch(metric_name: str, results: list[dict]) -> None:
    """Publish analytics results as CloudWatch metrics."""
    try:
        if not results:
            return

        metric_data = []

        # Handle different result formats
        for result in results:
            if "severity" in result and "count" in result:
                # Violation trends by severity
                metric_data.append(
                    {
                        "MetricName": f"{metric_name}_{result['severity']}",
                        "Value": float(result["count"]),
                        "Unit": "Count",
                        "Dimensions": [
                            {"Name": "Severity", "Value": result["severity"]}
                        ],
                    }
                )
            elif "high_risk_count" in result:
                # High risk principals count
                metric_data.append(
                    {
                        "MetricName": metric_name,
                        "Value": float(result["high_risk_count"]),
                        "Unit": "Count",
                    }
                )
            elif "attack_patterns" in result:
                # Potential attacks count
                metric_data.append(
                    {
                        "MetricName": metric_name,
                        "Value": float(result["attack_patterns"]),
                        "Unit": "Count",
                    }
                )

        if metric_data:
            cloudwatch_client.put_metric_data(
                Namespace="IAMPolicyMonitor/Analytics", MetricData=metric_data
            )
            print(f"📊 Published {len(metric_data)} metrics for {metric_name}")

    except Exception as e:
        print(f"⚠️ Failed to publish metrics for {metric_name}: {e!s}")


def handle_database_cleanup(database_name: str) -> dict[str, Any]:
    """
    Clean up Athena database by dropping all tables and views.
    This is called during terraform destroy when force_destroy_athena = true.
    """
    print("🧹 Starting Athena database cleanup...")

    results_bucket = RESULTS_BUCKET
    cleanup_results: dict[str, list[str]] = {
        "tables_dropped": [],
        "views_dropped": [],
        "errors": [],
    }

    try:
        # Get all tables and views in the database
        list_tables_query = f"SHOW TABLES IN {database_name}"

        query_id = execute_athena_query(
            list_tables_query,
            database_name,
            results_bucket,
            "Listing tables for cleanup",
        )

        # Get results
        results = get_query_results(query_id)

        # Drop each table/view
        for row in results:
            table_name = row.get(
                "tab_name", ""
            )  # SHOW TABLES returns 'tab_name' column

            if table_name:
                try:
                    # Try to drop as view first, then as table
                    drop_view_query = (
                        f"DROP VIEW IF EXISTS {database_name}.{table_name}"
                    )
                    execute_athena_query(
                        drop_view_query,
                        database_name,
                        results_bucket,
                        f"Dropping view {table_name}",
                    )
                    cleanup_results["views_dropped"].append(table_name)
                    print(f"✅ Dropped view: {table_name}")

                except Exception:
                    # If view drop fails, try as table
                    try:
                        drop_table_query = (
                            f"DROP TABLE IF EXISTS {database_name}.{table_name}"
                        )
                        execute_athena_query(
                            drop_table_query,
                            database_name,
                            results_bucket,
                            f"Dropping table {table_name}",
                        )
                        cleanup_results["tables_dropped"].append(table_name)
                        print(f"✅ Dropped table: {table_name}")

                    except Exception as e:
                        error_msg = f"Failed to drop {table_name}: {e!s}"
                        cleanup_results["errors"].append(error_msg)
                        print(f"❌ {error_msg}")

        print(
            f"🧹 Database cleanup completed. Dropped {len(cleanup_results['tables_dropped'])} tables and {len(cleanup_results['views_dropped'])} views"
        )

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Database cleanup completed successfully",
                    "cleanup_results": cleanup_results,
                }
            ),
        }

    except Exception as e:
        error_msg = f"Database cleanup failed: {e!s}"
        print(f"❌ {error_msg}")
        cleanup_results["errors"].append(error_msg)

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": "Database cleanup failed",
                    "error": error_msg,
                    "cleanup_results": cleanup_results,
                }
            ),
        }


def handle_analytics_execution(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Execute the analytics queries and publish metrics.
    This is called hourly by EventBridge.
    """
    print("📊 Starting analytics execution...")

    try:
        database_name = DATABASE_NAME
        results_bucket = RESULTS_BUCKET

        # Run automated metrics and publish to CloudWatch
        metrics_result = setup_automated_metrics(database_name, results_bucket)

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Analytics execution completed successfully",
                    "metrics": metrics_result,
                }
            ),
        }

    except Exception as e:
        error_msg = f"Analytics execution failed: {e!s}"
        print(f"❌ {error_msg}")

        return {
            "statusCode": 500,
            "body": json.dumps(
                {"message": "Analytics execution failed", "error": error_msg}
            ),
        }
