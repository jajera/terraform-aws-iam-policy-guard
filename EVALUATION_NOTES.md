# Evaluation Notes

Quick reference for evaluators and first-time users.

## Operational Tips

1. **Allow 2–3 minutes after `terraform apply`**
   CloudWatch log groups, EventBridge permissions and Lambda cold-starts need a short time to settle before you trigger demo events or run the post-deploy test commands.

2. **Debug logging is enabled in the example configs**
   The examples set `debug_mode = true`, which adds verbose JSON payloads to CloudWatch Logs. Switch to `false` for production use.

3. **Detection/remediation is *event driven***
   The module reacts only to *new* IAM events. Existing policies and users are unchanged unless they are subsequently modified.

4. **Tests are excluded from remediation**
   The default `suppress.yaml` file contains patterns that prevent the module from remediating resources created by its own tests.

5. **Demo Critical-Violation Alarm**
   A CloudWatch alarm named `<prefix>-critical-violations` is configured to flip to the `ALARM` state **only when the metric exceeds its threshold** (e.g., during the provided critical test event). Under normal operation the alarm remains in `OK`.

6. **SNS subscription confirmation e-mail**
   When `enable_sns_alerts = true`, AWS sends a "Subscription Confirmation" e-mail that can land in spam. Confirm it or disable SNS alerts for quicker demos.
