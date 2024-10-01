import os
import sys
from subprocess import check_call, check_output, STDOUT
from tempfile import NamedTemporaryFile

BASE_FLAG = 'openECSC{bring_back_the_good_old_java_reflection_%s}'


def gen_targets(flag: str) -> list[tuple[int, int, int]]:
    targets = []
    x, y, l = 0, 0, 0
    for c in flag.encode():
        match c & 3:
            case 0:
                x += (c >> 2) & 0b111
                y += c >> 5
            case 1:
                l += c >> 2
            case 2:
                l -= c >> 2
            case 3:
                magic = c >> 2
                x, y, l = x ^ magic, y ^ magic, l ^ magic

        targets.append((x, y, l))

    return targets


def main(userid: str):
    flag = BASE_FLAG % os.urandom(4).hex()
    targets = gen_targets(flag)

    with open('src/chall.go', 'r') as f:
        template = f.read()

    source = template.replace('/* TARGETS */', ',\n'.join(map(lambda x: f'{{{x[0]},{x[1]},{x[2]}}}', targets)) + ',')

    with NamedTemporaryFile('w+', dir=os.getcwd(), suffix='.go') as f:
        f.write(source)
        f.flush()

        check_call(['go', 'build', '-ldflags', '-s -w', '-o', f'../attachments/reflect/{userid}', f.name], cwd='src')

    out = check_output([f'attachments/reflect/{userid}'], input=flag.encode() + b'\n', stderr=STDOUT)
    assert out == b'correct\n'

    print(flag)


if __name__ == '__main__':
    main(sys.argv[1])
