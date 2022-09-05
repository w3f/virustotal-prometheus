/*eslint @typescript-eslint/no-use-before-define: ["error", { "variables": false }]*/

import { LoggerSingleton } from './logger';

const logger = LoggerSingleton.getInstance()

export async function asyncForEach<T>(array: Array<T>, callback: (arg0: T, arg1: number, arg2: Array<T>) => void): Promise<void> {
  for (let index = 0; index < array.length; index++) {
      await callback(array[index], index, array);
  }
}