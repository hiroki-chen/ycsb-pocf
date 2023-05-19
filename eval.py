#!/usr/bin/env python3

# Evaluate the remote database. This script is a simpler wrapper for the yscb script.

import argparse
import os
import subprocess

def main(args):
    tee_type = args.tee
    features = []
    print('[+] Doing evaluation for', tee_type)

    if tee_type.upper() == 'SGX':
        os.environ['TEE_TYPE'] = 'SGX'
        features.append('sgx')

    features = ','.join(features)
    command = 'cargo run -r --features=' + features + ' -- ' + args.operation + \
               ' -t '  + str(args.thread) + ' -w ' + args.workload + ' -a ' + args.address + \
               ' -p ' + str(args.port)

    # We dump the disk by default.
    if args.operation.upper() == 'LOAD':
        command += ' --enable-dump'

    print('[+] Executing the following command:')
    print('\t', command)

    runtime = 0
    throughput = 0
    for _ in range(args.num):
        # Invoke cargo and redirect stderr to stdout.
        p = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            print('[-] Command failed with', p.returncode)

        output = p.stdout.split('\n')

        # Analyze the output.
        result = [res for res in output if '[OVERALL]' in res]
        for res in result:
            if 'RunTime' in res:
                cur = float(res.split(' ')[-1])
                runtime += cur
            elif 'Throughput' in res:
                cur = float(res.split(' ')[-1])
                throughput += cur

    print('[+] Runtime: ', runtime / args.num, 'ms')
    print('[+] Throughput: ', throughput / args.num, 'op/s')

if __name__ == '__main__':
    # Create the argument parser
    parser = argparse.ArgumentParser(description='A wrapper for testing the performance of database using YCSB.')

    # Add arguments
    parser.add_argument('operation', type=str, help='Load/Run')
    parser.add_argument('--tee', type=str, help='The type of the TEE type the database uses', default='sgx')
    parser.add_argument('--thread', type=int, help='The thread number', default=1)
    parser.add_argument('--address', type=str, help='The address of the server', default='127.0.0.1')
    parser.add_argument('--port', type=int, help='The port of the server', default=1234)
    parser.add_argument('--workload', type=str, help='The path of the workload template file', default='./workloads/workloada.toml')
    parser.add_argument('--num', type=int, help='How many experiments should be performed', default=1)

    # Parse the arguments
    args = parser.parse_args()

    main(args)
