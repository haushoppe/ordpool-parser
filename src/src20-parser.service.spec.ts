import { decodeSrc20Transaction } from './src20-parser.service';
import { readTransaction } from './test.helper';

describe('SRC20 parser', () => {

  it('should parse SRC-20 Transactions', () => {

    const txn = readTransaction('50aeb77245a9483a5b077e4e7506c331dc2f628c22046e7d2b4c6ad6c6236ae1');

    const decodedData = decodeSrc20Transaction(txn);
    console.log(decodedData);
  });
});