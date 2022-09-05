import * as promClient from 'prom-client';
import { Logger, LoggerSingleton } from './logger';
import { PromClient } from './types';

export class Prometheus implements PromClient {

    private virustotalReports: promClient.Gauge<"domain">;

    private readonly logger: Logger = LoggerSingleton.getInstance()

    constructor() {
        this._initMetrics()
        this.startCollection()
    }

    
    startCollection(): void {
        this.logger.info(
            'Starting the collection of metrics, the metrics are available on /metrics'
        );
        promClient.collectDefaultMetrics();
    }

    setVTReports(domain: string, reports: number): void{
      this.virustotalReports.set({domain}, reports);        
    }

    _initMetrics(): void {
        this.virustotalReports = new promClient.Gauge({
            name: 'virustotal_reports',
            help: 'Virustotal bad status report for a specific domain',
            labelNames: ['domain']
        });
    }
}
