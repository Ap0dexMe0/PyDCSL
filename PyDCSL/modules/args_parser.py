import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(
        description="Widevine DCSL extractor: either provide a .wvd file or both client_id.bin and private_key.pem."
    )

    # Primary modes
    parser.add_argument(
        '-f', '--file',
        dest='wvd_file',
        metavar='WVD_FILE',
        help='Path to the .wvd input file'
    )
    parser.add_argument(
        '-c', '--client-id',
        dest='client_id',
        metavar='CLIENT_ID',
        help='Path to client_id.bin'
    )
    parser.add_argument(
        '-p', '--private-key',
        dest='private_key',
        metavar='PRIVATE_KEY',
        help='Path to private_key.pem'
    )

    # Output
    parser.add_argument(
        '-o', '--output',
        dest='output',
        metavar='OUTPUT',
        default=None,
        help='Path to write the resulting JSON (defaults to MODEL_NAME.json)'
    )

    args = parser.parse_args()

    # Validate that either -f is given, or both -c and -p
    if not args.wvd_file:
        if not (args.client_id and args.private_key):
            parser.error("You must specify either -f/--file or both -c/--client-id and -p/--private-key.")
        if args.client_id and not args.private_key:
            parser.error("--private-key is required when using --client-id")
    else:
        args.client_id = None
        args.private_key = None
    return args