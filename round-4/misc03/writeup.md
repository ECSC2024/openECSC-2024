# openECSC 2024 - Round 4

## [misc] Malware and snapshots (18 solves)

We got infected by a malware, it was writing and deleting files on our server, luckly we had a service that snapshotted the filesystem continuosly.

We need to know what was the malware doing, can you help us?

Author: Luca Massarelli <@ACN>, Bruno Taricco <@ACN>, Lorenzo Zarfati <@ACN>, Giovanni Minotti <@Giotino>

## Solution

You have found two essential pieces of information:
- the script used to encrypt the command and control configuration of the malware;
- a set of ZFS snapshots of a filesystem.;

Let's starting with importing all the snapshots with `zfs receive pool/test < ./snapshots/{file}` for each file and then mounting the filesystem. We can then look for the files and analyze them.

By looking at the script, you can easily see that it has an hardcoded URL of the C&C (that is, the flag) and a folder where to write the malware configuration. After taking these values as input, the script produced files with random names inside the given folder. However, one contains the key - XORed with a randomly generated nonce and then encoded - used to encrypt the malware configuration. The latter is then stored in the file 'configuration. encrypted' in the same folder. 

We first need to identify the file containing the key to find the flag. Then, we can use it to decrypt the configuration file and read the flag.

By looking at the encryption script, we can observe that it writes a test file named 'test_file_write.txt' before writing the others to see if it has writing permission for the folder. This is very useful because the seed for the PRNG is set after writing this file; hence, by looking at the creation time of this file, we can obtain a timestamp to use as a seed for the PRNG. In this way, we can reconstruct all the random values generated in the process and retrieve the name of the file containing the key. Once we obtain the file name, we can obtain the nonce value similarly. Note that after writing the test file and before setting the seed for the PRNG there is a call to the sleep function. Therefore it is necessary to try different values starting for the timestamp corresponding the the creation time and incrementing it by one until the key is found. 

Now, we don't have the file available, but remember that we have imported a lot of snapshots; by setting `snapdir` to `visible` (`zfs set snapdir=visible pool/test`) ZFS will create a `.zfs/snapshot` directory in the root of our dataset containing all the snapshots. We can then navigate to the snapshot containing the file and retieve its content.

Finally, we get the key to decrypt the configuration by reading the file, decoding its content, and XORing it with the nonce.  

Check out the [snapshots importer](writeup/import_snapshots.py) and the [solver script](writeup/solve.py)!
