#!/usr/bin/env node

import yargs, { check } from 'yargs';
import { CheckPhish } from '@timjohns/checkphish';

const DEFAULT_CHECKPHISH_API_POLL_RETRIES = 30;
const DEFAULT_POLL_INTERVAL_MS = 1000;

// TODO(tjohns): if no api key is specified, try to read one from a .rc file
// TODO(tjohns): Add help
//   Note for help: 'insights' is a special case - defaults to true if not supplied,
//   and false must be explicitly requested with "--no-insights",
//   see https://yargs.js.org/docs/#api-reference-booleankey
const args = yargs.options({
  'api-key': { type: 'string', demandOption: true, alias: 'a' },
  'url': { type: 'string', demandOption: true, alias: 'u' },
  'insights': { type: 'boolean', alias: 'i' },
  'pollintervalms': { type: 'number', alias: 'm', default: DEFAULT_POLL_INTERVAL_MS },
  'pollretries': { type: 'number', alias: 'r', default: DEFAULT_CHECKPHISH_API_POLL_RETRIES },
  'verbose': { type: 'count', alias: 'v' }
}).argv;

const VERBOSE_LEVEL = args.verbose;

function WARN(...args: any[])  { VERBOSE_LEVEL >= 0 && console.log(...args); }
function INFO(...args: any[])  { VERBOSE_LEVEL >= 1 && console.log(...args); }
function DEBUG(...args: any[]) { VERBOSE_LEVEL >= 2 && console.log(...args); }

const CHECKPHISH_API_POLL_RETRIES = args.pollretries;
const POLL_INTERVAL_MS = args.pollintervalms;

const checkphish = new CheckPhish(args.apiKey as string);

const scan = async () => {

  // TODO DELETEME
  console.log('insights: ', args.insights);

  try {

    const scanResponse = await checkphish.scan(args.url);

    DEBUG(JSON.stringify({scanResponse}, null, 2));

    // TODO(tjohns): Find a better way to avoid 'as string'
    await pollStatus(checkphish, scanResponse.jobID as string);

    async function pollStatus(checkphish: CheckPhish, jobID: string, retries = 0) {

      // TODO(tjohns): Consider reversing the polarity on the default for 'insights',
      // but for now, consider that if insights is 'false', the disposition doesn't
      // appear to be meaningful. Might be worth reaching out to Bolster for more
      // guidance.
      const statusResponse = await checkphish.status(jobID, args.insights);

      DEBUG(JSON.stringify({statusResponse}, null, 2));

      if (statusResponse.status == 'DONE') {

        // TODO(tjohns): Ask Bolster team about listing these out in the API docs

        // default to whatever CheckPhish returned, verbatim
        let disposition = `*${statusResponse.disposition}*`;
        switch (statusResponse.disposition) {
          case 'clean':
            if (statusResponse.resolved) {
              disposition = 'Resolved clean.';
            } else {
              disposition = 'Unable to resolve at this time, please try again later.'
              if (!args.insights) {
                disposition += " Consider trying again with the 'insights' flag set.";
              }
             }
            break;
          case 'phish':
            disposition = 'Phishing'
            break;
          case 'suspicious':
            disposition = 'Suspicious';
            break;
        }

        console.log(`Scanned ${statusResponse.url}\ndisposition: ${disposition}`);

      } else if (statusResponse.status == 'PENDING') {

        if (retries >= CHECKPHISH_API_POLL_RETRIES) {

          const message = `Timeout scanning ${statusResponse.url}, jobID: ${jobID}. Please try again later.`
          throw new Error(message);


        } else {

          return new Promise((resolve, reject) => {
            retries++;
            setTimeout(() => {
              pollStatus(checkphish, jobID, retries)
              .then(resolve)
              .catch(reject);
            }, POLL_INTERVAL_MS);
          })
        }
      } else {
        throw Error(`Unexpected status from CheckPhish API: ${statusResponse.status}`);
      }
    };
  } catch (e) {
    if (VERBOSE_LEVEL >= 1) {
      console.error(e);
    } else {
      console.error(e.message);
    }
  }
}

scan();






