# Roadmap / Future Ideas

This file tracks potential enhancements that were out-of-scope for the initial release but would add value in future iterations.

## Notification Enhancements

- [ ] **Configurable message templates** for SNS/Slack to let users fully customise subject lines and payload layouts.
- [ ] **Automatic remediation for MEDIUM severity** violations (currently only HIGH/CRITICAL supported).
- [ ] **Improve email formatting** – HTML+text multipart with branded styling.

## Detection Engine

- [ ] Expand ruleset and experiment with **machine-learning-assisted rule generation**.
- [ ] Enhance severity calculation where multiple rules apply (take the _highest_ severity instead of first match).

## Operational Controls

- [ ] **Rate limiting** for remediation actions (`actions_per_minute`, `actions_per_hour`).
- [ ] Support `max_batch_size` configuration for the Remediator SQS event source mapping.

## AI / Analytics

- [ ] **AI-powered infrastructure monitoring** (Gen-AI summarisation of trends & anomalies).

Feel free to open issues or PRs if you'd like to tackle any of these ideas!
