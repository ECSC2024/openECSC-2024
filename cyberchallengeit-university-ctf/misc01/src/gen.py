#!/usr/bin/env python3
import os
import random
import string
import tempfile
import subprocess
import sys
from solve import solve


original_dir = os.getcwd()


def cmd(command):
    #print(command)
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not result:
        print(f"Failed: {command}")
        exit(1)


def random_string():
    return "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(16)
    )


def gen_xxd(infile, outdir, outfilename):
    cmd(f"xxd {infile} > {outdir}/{outfilename}.hex")
    return f"{outfilename}.hex"


def gen_base64(infile, outdir, outfilename):
    cmd(f"base64 {infile} > {outdir}/{outfilename}.b64")
    return f"{outfilename}.b64"


def gen_zip(infile, outdir, outfilename):
    cmd(f"zip -P password {outdir}/{outfilename}.zip {infile}")
    return f"{outfilename}.zip"


def gen_7z(infile, outdir, outfilename):
    cmd(f"7z a -ppassword {outdir}/{outfilename}.7z {infile}")
    return f"{outfilename}.7z"


def gen_tar(infile, outdir, outfilename):
    cmd(f"tar -czvf {outdir}/{outfilename}.tar.gz {infile}")
    return f"{outfilename}.tar.gz"


def gen_gzip(infile, outdir, outfilename):
    cmd(f"gzip -c {infile} > {outdir}/{outfilename}.gz")
    return f"{outfilename}.gz"


def gen_bzip2(infile, outdir, outfilename):
    cmd(f"bzip2 -c {infile} > {outdir}/{outfilename}")
    return f"{outfilename}"


def gen_xz(infile, outdir, outfilename):
    cmd(f"xz -c {infile} > {outdir}/{outfilename}.xz")
    return f"{outfilename}.xz"


def gen_fat(infile, outdir, outfilename):
    cmd(f"mkfs.vfat -C {outdir}/{outfilename}.fat 1440")
    cmd(f"mcopy -i {outdir}/{outfilename}.fat {infile} ::/")
    return f"{outfilename}.fat"


def gen_ext4(infile, outdir, outfilename):
    cmd(f"dd if=/dev/zero of={outdir}/{outfilename}.ext4 bs=5M count=1")
    cmd(f"mkfs.ext4 {outdir}/{outfilename}.ext4")
    cmd(f"mount {outdir}/{outfilename}.ext4 /mnt")
    cmd(f"cp {infile} /mnt/")
    cmd(f"umount /mnt")
    return f"{outfilename}.ext4"


def temp_directory():
    return tempfile.mkdtemp()


def gen_attachment(seed):
    os.chdir(original_dir)
    random.seed(seed)
    flag = "CCIT{apt_install_everything_" + os.urandom(4).hex() + "}"
    print(flag)

    prevdir = temp_directory()
    prevfilename = "flag.txt"
    with open(f"{prevdir}/{prevfilename}", "w") as f:
        f.write(flag)
    for _ in range(50):
        function = random.choice(
            [gen_xxd, gen_base64, gen_zip, gen_7z, gen_tar, gen_gzip, gen_bzip2, gen_xz]
        )
        outdir = temp_directory()
        outfilename = random_string()
        os.chdir(prevdir)
        prevfilename = function(prevfilename, outdir, outfilename)
        prevdir = outdir

    os.chdir(prevdir)
    gen_zip(prevfilename, f"{original_dir}/attachments/challenge.zip", f"{seed}")
    cmd(f"mv {original_dir}/attachments/challenge.zip/{seed}.zip  {original_dir}/attachments/challenge.zip/{seed}")
    os.chdir(original_dir)
    return flag


def gen_and_solve(i):
    generated_flag = gen_attachment(i)
    with tempfile.TemporaryDirectory() as tmpdir:
        os.system(f"cp {original_dir}/attachments/challenge.zip/{i} {tmpdir}/{i}.zip")
        os.chdir(tmpdir)
        extracted_flag = solve(f"{i}.zip")
        os.chdir(original_dir)
        if generated_flag != extracted_flag:
            print("Failure")
            exit(1)

gen_and_solve(int(sys.argv[1]))
