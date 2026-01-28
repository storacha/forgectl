# forgectl

Admin tools for the Storacha Forge network.

## Install

Clone the repo and then in the root directory:

```sh
make install
```

## Usage

1. Create your network config file using `config.template.yaml` as a base.
2. Use CLI command passing the config: `forgectl --config ./config.yaml ...`

## Metrics

Export payment and fault metrics via OTLP for monitoring.

### Payment Metrics

Collect payment channel metrics (funds, lockup, runway):

```sh
forgectl metrics payments \
  --config ./config.yaml \
  --payer 0xYourPayerAddress \
  --otlp-endpoint otel-collector.example.com:4318
```

**Metrics exported:**
- `forgectl_payer_funds` - Total deposited funds (USDFC)
- `forgectl_payer_lockup_current` - Current lockup amount (USDFC)
- `forgectl_payer_runway_seconds` - Estimated time until funds depleted

### Fault Metrics

Collect proof fault metrics (missed proving periods):

```sh
forgectl metrics faults \
  --config ./config.yaml \
  --payer 0xYourPayerAddress \
  --otlp-endpoint otel-collector.example.com:4318
```

**Metrics exported:**
- `forgectl_rail_missed_periods` - Count of missed proving periods per dataset

### Flags

| Flag | Description |
|------|-------------|
| `--payer` | Payer address to monitor (required) |
| `--otlp-endpoint` | OTLP HTTP endpoint (required) |
| `--otlp-insecure` | Use HTTP instead of HTTPS |

### Cron Usage

Both commands collect metrics once and exit, making them suitable for cron jobs:

```sh
# Payment metrics every 30 minutes
*/30 * * * * /path/to/forgectl metrics payments --config /path/to/config.yaml --payer 0x... --otlp-endpoint ...

# Fault metrics every 12 hours
0 */12 * * * /path/to/forgectl metrics faults --config /path/to/config.yaml --payer 0x... --otlp-endpoint ...
```

GitHub Actions workflows are also provided in `.github/workflows/` for automated collection.
