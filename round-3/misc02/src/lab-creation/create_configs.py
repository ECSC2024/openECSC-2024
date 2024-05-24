from base58 import b58encode
import os

def random_password():
    return b58encode(os.urandom(16)).decode() + "1"

ADMIN_USERNAME = "Amministratore"
DEPLOY_USERNAME = "Distributore"

FACT_WS_ADMIN_PASSWORD = random_password()
FACT_WS_DEPLOY_PASSWORD = random_password()
FACT_RODC_ADMIN_PASSWORD = random_password()
FACT_RODC_DEPLOY_PASSWORD = random_password()
MGMT_DC_ADMIN_PASSWORD = random_password()
MGMT_DC_DEPLOY_PASSWORD = random_password()
HQDC_ADMIN_PASSWORD = random_password()
HQDC_DEPLOY_PASSWORD = random_password()
SILVIA_PASSWORD = random_password()

# Generate SSH keys and save to `ssh_keys/lab`
os.makedirs("ssh_keys", exist_ok=True)
os.remove("ssh_keys/lab") if os.path.exists("ssh_keys/lab") else None
os.remove("ssh_keys/lab.pub") if os.path.exists("ssh_keys/lab") else None
os.system("ssh-keygen -t rsa -b 2048 -f ssh_keys/lab -N '' -C 'lab'")

ROUTER_SSH_RSA_PUB = open("ssh_keys/lab.pub").read().strip()

# Generate WireGuard keys
os.makedirs("wg_keys", exist_ok=True)
os.remove("wg_keys/private") if os.path.exists("wg_keys/private") else None
os.remove("wg_keys/public") if os.path.exists("wg_keys/public") else None
os.system("wg genkey | tee wg_keys/private.key | wg pubkey > wg_keys/public.key")

WG_PRIVATE_KEY = open("wg_keys/private.key").read().strip()

# Find all files that end with '.template' in the current directory nested and replace the placeholders with the generated values
for root, _, files in os.walk("./deployment"):
    for filename in files:
        if filename.endswith(".template"):
            with open(f"{root}/{filename}", "r") as f:
                content = f.read()
                content = content.replace("<ADMIN_USERNAME>", ADMIN_USERNAME)
                content = content.replace("<DEPLOY_USERNAME>", DEPLOY_USERNAME)
                content = content.replace("<FACT_WS_ADMIN_PASSWORD>", FACT_WS_ADMIN_PASSWORD)
                content = content.replace("<FACT_WS_DEPLOY_PASSWORD>", FACT_WS_DEPLOY_PASSWORD)
                content = content.replace("<FACT_RODC_ADMIN_PASSWORD>", FACT_RODC_ADMIN_PASSWORD)
                content = content.replace("<FACT_RODC_DEPLOY_PASSWORD>", FACT_RODC_DEPLOY_PASSWORD)
                content = content.replace("<MGMT_DC_ADMIN_PASSWORD>", MGMT_DC_ADMIN_PASSWORD)
                content = content.replace("<MGMT_DC_DEPLOY_PASSWORD>", MGMT_DC_DEPLOY_PASSWORD)
                content = content.replace("<HQDC_ADMIN_PASSWORD>", HQDC_ADMIN_PASSWORD)
                content = content.replace("<HQDC_DEPLOY_PASSWORD>", HQDC_DEPLOY_PASSWORD)
                content = content.replace("<SILVIA_PASSWORD>", SILVIA_PASSWORD)
                content = content.replace("<ROUTER_SSH_RSA_PUB>", ROUTER_SSH_RSA_PUB)
                content = content.replace("<WG_PRIVATE_KEY>", WG_PRIVATE_KEY)

                # Repeatedly replace '<RANDOM_PASSWORD>' with a new random password
                while "<RANDOM_PASSWORD>" in content:
                    content = content.replace("<RANDOM_PASSWORD>", random_password(), 1)

                with open(f"{root}/{filename.replace('.template', '')}", "w") as f:
                    f.write(content)