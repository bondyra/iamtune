import argparse


parser = argparse.ArgumentParser(
                    prog='iamtune',
                    description='dasdsad',
                    exit_on_error=False
)

parser.add_argument('--profile')
parser.add_argument('--profiles')
parser.add_argument('-r', '--role')
parser.add_argument('--roles')
parser.add_argument('--role-arn')
parser.add_argument('--role-arns')
parser.add_argument('-p', '--policy')
parser.add_argument('--policies')
parser.add_argument('--policy-arn')
parser.add_argument('--policy-arns')
parser.add_argument('-a', '--all')
parser.add_argument('-t')
parser.add_argument('-v', '--verbose',
                    action='store_true')

def main():  # pragma: no cover
    args = parser.parse_args()
    print(args)
