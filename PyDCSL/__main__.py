import sys

from PyDCSL.modules.banners import clear_and_print
from PyDCSL.modules.args_parser import parse_args
from PyDCSL.modules.logging import setup_logging
from PyDCSL.modules.dcsl import dcsl


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    clear_and_print()
    args = parse_args()
    setup_logging()
    dcsl(
        wvd_file=args.wvd_file,
        client_id=args.client_id,
        private_key=args.private_key,
        output=args.output,
    )

if __name__ == '__main__':
    main()