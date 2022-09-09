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

const logger = LoggerSingleton.getInstance()


function lookup(vtApi: any, promClient: Prometheus, domain: string){
    logger.debug(`triggering a lookup for the domain ${domain}`)
    vtApi.domainLookup(domain,function(err, res){
        if (err) {
        logger.error(`Error on processing ${domain}`);
        logger.error(err);
        process.exit(-1)
        }

        const parsed = JSON.parse(res)
        const reports =  parsed.data.attributes.last_analysis_stats.malicious + parsed.data.attributes.last_analysis_stats.suspicious
        logger.info(`${domain} reports: ${reports}`);
        promClient.setVTReport(domain,reports)
        return;
    })
    logger.debug(`lookup for the domain ${domain} DONE`)
}

async function ibmLookup(apiToken: string, apiPassword: string ,promClient: Prometheus, domain: string){
    logger.debug(`triggering a ibm lookup for the domain ${domain}`)
    const url = `https://api.xforce.ibmcloud.com/api/url/${domain}`;
    const options = {
        headers: {
            'accept': 'application/json',
            'Authorization': 'Basic ZGQ0YTM0OGEtZmYzNy00YWZjLWEyMWItMDI3MzE0OWYxZDY3OjRmOTQ1YmRiLTk2MTYtNDY3My05YWY4LWUyNDI1OTllODc1NA=='
        },
    };

    try {
        const response: any = await got(url,options).json();
        const score: number = response.result.score
        logger.info(`${domain} ibm score, 1 is good: ${score}`);
        promClient.setIbmScore(domain,score)
        
    } catch (error) {
        logger.error(`Error on ibm processing ${domain}`);
        logger.error(error);
        process.exit(-1)
    }
    
    logger.debug(`lookup for the domain ${domain} DONE`)
}

export async function startAction(cmd): Promise<void> {

    const cfg = new Config<InputConfig>().parse(cmd.config);
    LoggerSingleton.setInstance(cfg.logLevel)

    const domainsSet = new Set<string>()

    if(cfg.targetDomains.cloudflare.enabled){
        const cf = cloudflare({
            token: cfg.targetDomains.cloudflare.apiKey
        });

        try {
            const zones = await cf.zones.browse()
            zones.result.forEach(element => {
                domainsSet.add(element.name)
            });
        } catch (error) {
            logger.error(`Error on processing the clouflare api`);
            logger.error(error);
            process.exit(-1)
        }
    }

    const manualList = cfg.targetDomains.manualList ? cfg.targetDomains.manualList : []
    manualList.forEach(domain=>domainsSet.add(domain))
    const targetDomains = Array.from( domainsSet.values() )

    logger.info(targetDomains.toString())
    
    const server = express();
    server.get('/healthcheck',
        async (req: express.Request, res: express.Response): Promise<void> => {
            res.status(200).send('OK!')
        })
    server.get('/metrics', async (req: express.Request, res: express.Response) => {
            res.set('Content-Type', register.contentType)
            res.end(await register.metrics())
        })    
    server.listen(cfg.port);
    
    const api = vt.makeAPI();
    api.setKey(cfg.virusTotal.apiKey)
    const promClient = new Prometheus();
    const evalInterval = cfg.evalIntervalMinutes? cfg.evalIntervalMinutes*1000*60 : evalIntervalMinutes
    targetDomains.forEach(domain=>lookup(api,promClient,domain)) 
    setInterval(
        () => targetDomains.forEach(domain => {
            lookup(api,promClient,domain)
            if(cfg.ibmXforce.enabled) ibmLookup(cfg.ibmXforce.apiToken,cfg.ibmXforce.apiPassword,promClient,domain)
        }),
        evalInterval
    )
}
