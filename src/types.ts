
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
    ibmXforce: {
        enabled: boolean;
        apiKey: string;
        apiPassword: string;
    };
}

export interface PromClient {
    setVTReport(domain: string, reports: number): void;
    setIbmScore(domain: string, score: number): void;
}