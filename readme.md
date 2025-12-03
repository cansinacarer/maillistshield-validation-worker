# Mail List Shield - Email Validation Worker

[![Build and Deploy Worker 1](https://github.com/cansinacarer/maillistshield-validation-worker/actions/workflows/deploy-worker-1.yml/badge.svg)](https://github.com/cansinacarer/maillistshield-validation-worker/actions/workflows/deploy-worker-1.yml)
[![Build and Deploy Worker 2](https://github.com/cansinacarer/maillistshield-validation-worker/actions/workflows/deploy-worker-2.yml/badge.svg)](https://github.com/cansinacarer/maillistshield-validation-worker/actions/workflows/deploy-worker-2.yml)
[![Unit Tests](https://github.com/cansinacarer/maillistshield-validation-worker/actions/workflows/ci.yml/badge.svg)](https://github.com/cansinacarer/maillistshield-validation-worker/actions/workflows/ci.yml)

This service performs the email validation. It takes API requests with an API key and responds with the validation result JSON shown at [maillistshield.com](https://maillistshield.com) home page.

#### Deployment note

This service should be deployed in multiple servers in different IP blocks (preferably in different regions) because the success of the validation depends on the IP reputation determined by the email service providers. A worker in one server might return an unknown result while another instance that is deployed on a server with a different IP reputation can find a valid result.

The other services that use this worker try multiple workers and use the best result.

**Job States:**

This service does not change the job state, because it only works with individual email addresses and is unaware of the files.

---

See the [main repository](https://github.com/cansinacarer/maillistshield-com) for a complete list of other microservices.
