
export interface InputConfig {
    logLevel: string;
    port: number;
    targetDomains: Array<string>;
    evalIntervalMinutes?: number;
    virusTotal: {
        apiKey: string;
    };
}

export interface PromClient {
    setVTReports(domain: string, reports: number): void;
}