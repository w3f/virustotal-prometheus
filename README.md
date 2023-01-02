[![CircleCI](https://circleci.com/gh/w3f/virustotal-prometheus.svg?style=svg)](https://circleci.com/gh/w3f/virustotal-prometheus)

# virustotal-prometheus

App to monitor (mainly) VirusTotal reports and to expose Prometheus metrics.  

The application is K8s ready, and it provides also a ServiceMonitor and a PrometheusRule configurations that can be used by your Prometheus/Alertmanager.

## Intelligence sources

- VirusTotal
- IBM Xforce (optional)

## Domain List

It can be configured via a [config file](/config/main.sample.yaml). 

### Api sources for the domain list
- Cloudflare (optional):  
the domain list can be dynamically enriched via Clodflare. Please set up this connection with a read-only apiKey.

## How to Run

```
yarn
yarn start -c path_to_config_file
```test
