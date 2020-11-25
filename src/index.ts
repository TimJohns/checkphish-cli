#!/usr/bin/env node

import yargs, { check } from 'yargs';
import { CheckPhish } from '@timjohns/checkphish';

// TODO(tjohns): Take as an argument
const CHECKPHISH_API_POLL_RETRIES = 30;
// TODO(tjohns): Take as an argument
const POLL_INTERVAL_MS = 1000;

// TODO(tjohns): Take insights, et. al. as arguments
const args = yargs.options({
  'api-key': { type: 'string', demandOption: true, alias: 'a' },
  'url': { type: 'string', demandOption: true, alias: 'u' },
  'instructions': { type: 'array', demandOption: true, alias: 'i' },
}).argv;

const checkphish = new CheckPhish(args.apiKey as string);

const scan = async () => {
  const scanResponse = await checkphish.scan(args.url);

  // TODO(tjohns): Find a better way to avoid 'as string'
  await pollStatus(checkphish, scanResponse.jobID as string);

  async function pollStatus(checkphish: CheckPhish, jobID: string, retries = 0) {

    const statusResponse = await checkphish.status(jobID);

    if (statusResponse.status == 'DONE') {

      // TODO(tjohns): Ask Bolster team about listing these out in the API docs

      // default to whatever CheckPhish returned, verbatim
      let disposition = `*${statusResponse.disposition}*`;
      switch (statusResponse.disposition) {
        case 'clean':
          if (statusResponse.resolved) {
            disposition = '*clean* :white_check_mark:';
          } else {
            disposition = 'unable to resolve at this time, please try again later.'
          }
          break;
        case 'phish':
          disposition = '*phish* :no_entry:'
          break;
        case 'suspicious':
          disposition = '*suspicious* :face_with_raised_eyebrow:';
          break;
      }

      console.log(`Scanned ${statusResponse.url}\ndisposition: ${disposition}`);

    } else if (statusResponse.status == 'PENDING') {

      if (retries > CHECKPHISH_API_POLL_RETRIES) {

        const message = `Timeout scanning ${statusResponse.url}. Please try again later.`
        console.warn(JSON.stringify({message, jobID}));
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

}

scan();






