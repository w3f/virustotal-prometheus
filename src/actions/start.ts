import express from 'express';
import { LoggerSingleton } from '../logger'
import { Config } from '@w3f/config';
import { Prometheus } from '../prometheus';
import { register } from 'prom-client';
import { InputConfig } from '../types';
import { evalIntervalMinutes } from '../constants';
import vt from 'node-virustotal'
import cloudflare from 'cloudflare'
import got from 'got'

interface lookupConfig {
    vtApi: any;
    ibmApiKey?: string;
    ibmPassword?: string;
    ibmEnabled: boolean;
    promClient: Prometheus;
}

var logger = LoggerSingleton.getInstance()

async function lookup(config: lookupConfig, domain: string): Promise<void> {
    vtLookup(config.vtApi,config.promClient,domain)
    if(config.ibmEnabled) await ibmLookup(config.ibmApiKey,config.ibmPassword,config.promClient,domain)
}

function vtLookup(vtApi: any, promClient: Prometheus, domain: string){
    logger.debug(`triggering a Virustotal lookup for the domain ${domain}`)
    vtApi.domainLookup(domain,function(err, res){
        if (err) {
        logger.error(`Error on VT processing ${domain}`);
        logger.error(err);
        process.exit(-1)
        }

        const parsed = JSON.parse(res)
        const reports =  parsed.data.attributes.last_analysis_stats.malicious + parsed.data.attributes.last_analysis_stats.suspicious
        logger.info(`${domain} reports: ${reports}`);
        promClient.setVTReport(domain,reports)
        logger.debug(`VT lookup for the domain ${domain} DONE`)
    })
}

async function ibmLookup(apiKey: string, apiPassword: string ,promClient: Prometheus, domain: string){
    logger.debug(`triggering an IBM lookup for the domain ${domain}`)
    const url = `https://api.xforce.ibmcloud.com/api/url/${domain}`;

    const options = {
        headers: {
            'accept': 'application/json',
            'Authorization': `Basic ${Buffer.from(`${apiKey}:${apiPassword}`).toString("base64")}`
        },
    };

    try {
        const response: any = await got(url,options).json();
        logger.info(JSON.stringify(response))
        const score: number = response.result.score? response.result.score : 1 //unkown is treated as OK
        logger.info(`${domain} ibm score, 1 is OK: ${score}`);
        promClient.setIbmScore(domain,score)
        logger.debug(`IBM lookup for the domain ${domain} DONE`)
    } catch (error) {
        const errorMessage: string = error.toString()
        if(errorMessage.includes("404")){
            logger.warn(`IBM api is not capable of processing ${domain}`)
            logger.warn(errorMessage);
        } else{
            logger.error(`Error on IBM processing ${domain}`);
            logger.error(error);
            process.exit(-1)
        }
    }
}

function configureServerEndpoints(server: express.Express): void {
    server.get('/healthcheck',
        async (req: express.Request, res: express.Response): Promise<void> => {
            res.status(200).send('OK!')
        })
    server.get('/metrics', async (req: express.Request, res: express.Response) => {
            res.set('Content-Type', register.contentType)
            res.end(await register.metrics())
        })    
}

async function cfAddDomains(apiKey: string, domains: Set<string>): Promise<void> {
    const cf = cloudflare({
        token: apiKey
    });

    try {
        const zones = await cf.zones.browse()
        zones.result.forEach(element => {
            domains.add(element.name)
        });
    } catch (error) {
        logger.error(`Error on processing the clouflare api`);
        logger.error(error);
        process.exit(-1)
    }
}

export async function startAction(cmd): Promise<void> {

    const cfg = new Config<InputConfig>().parse(cmd.config);
    logger = LoggerSingleton.getNewInstance(cfg.logLevel)

    const domainsSet = new Set<string>()
    if(cfg.targetDomains.cloudflare.enabled){
        await cfAddDomains(cfg.targetDomains.cloudflare.apiKey,domainsSet)
    }
    const manualList = cfg.targetDomains.manualList ? cfg.targetDomains.manualList : []
    manualList.forEach(domain=>domainsSet.add(domain))
    const targetDomains = Array.from( domainsSet.values() )
    logger.info(`Target List: ${targetDomains.toString()}`)
    
    const server = express();
    configureServerEndpoints(server)
    server.listen(cfg.port);

    const promClient = new Prometheus();
    const evalInterval = cfg.evalIntervalMinutes? cfg.evalIntervalMinutes*1000*60 : evalIntervalMinutes
    
    const vtApi = vt.makeAPI();
    vtApi.setKey(cfg.virusTotal.apiKey)

    const lookupConfig = {
        vtApi: vtApi,
        ibmApiKey: cfg.ibmXforce.apiKey,
        ibmPassword: cfg.ibmXforce.apiPassword,
        ibmEnabled: cfg.ibmXforce.enabled,
        promClient: promClient
    }
    targetDomains.forEach(domain => lookup(lookupConfig,domain)) 
    setInterval(
        () => targetDomains.forEach(domain => lookup(lookupConfig,domain)),
        evalInterval
    )
}
