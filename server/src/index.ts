#!/usr/bin/env node
import { runCli } from './cli';

runCli(process.argv.slice(2)).catch(error => {
  console.error('[RedProxy] fatal:', error);
  process.exitCode = 1;
});
