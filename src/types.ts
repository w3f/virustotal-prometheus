
export interface InputConfig {
    logLevel: string;
    port: number;
    targetDomains: {
        manualList?: Array<string>;
        cloudflare: {
            enabled: boolean;
            apiKey: string;
        };
    } ;
    evalIntervalMinutes?: number;
    virusTotal: {
        apiKey: string;
    };
}

export interface PromClient {
    setVTReports(domain: string, reports: number): void;
}