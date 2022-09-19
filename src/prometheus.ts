import * as promClient from 'prom-client';
import { Logger, LoggerSingleton } from './logger';
import { PromClient } from './types';

export class Prometheus implements PromClient {

    private virustotalReports: promClient.Gauge<"domain">;
    private ibmScore: promClient.Gauge<"domain">;

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

    setVTReport(domain: string, reports: number): void{
      this.virustotalReports.set({domain}, reports);        
    }
    setIbmScore(domain: string, score: number): void{
        this.ibmScore.set({domain}, score);        
      }

    _initMetrics(): void {
        this.virustotalReports = new promClient.Gauge({
            name: 'virustotal_reports',
            help: 'Virustotal bad status report for a specific domain',
            labelNames: ['domain']
        });
        this.ibmScore = new promClient.Gauge({
            name: 'ibm_xforce_score',
            help: 'Ibm xforce score for a specific domain, 1 is good',
            labelNames: ['domain']
        });
    }
}
