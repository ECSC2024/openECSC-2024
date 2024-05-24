# Deployment

The following commands can be used to deploy the lab. The deployment is done in Azure and the lab is created using Ansible.

The CPU type used is `Standard_B2ls_v2` which requires increased quota. Feel free to change `*_vmSize` in `./deployment/azure/template_deployment_template.json` to a different value.

```bash
# Fill out templates with random variables (passwords, etc.)
python3 create_configs.py

# Create resource groups
az deployment sub create --location <AZURE_LOCATION> --template-file ./deployment/azure/resource_groups_deployment.json

# Create VMs
az deployment group create --resource-group "lab-template-deployment" --mode Complete --template-file ./deployment/azure/template_deployment_template.json --parameters ./deployment/azure/template_deployment_template.variables.json --query properties.outputs.labIp.value

# Get IP and change <LAB_IP> in ./deployment/ansible/router/inventory 

ansible-playbook -i deployment/ansible/router/inventory deployment/ansible/router/main.yml

# SSH on to router

ssh -i ssh_keys/lab deploy@<LAB_IP>

# Temporarily allow internet access
sudo iptables -P FORWARD ACCEPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

cd ./lab
ansible-playbook -i inventory main.yml

# Revert internet access
sudo iptables -P FORWARD DROP
sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Exit and copy artifacts
scp -r -i ssh_keys/lab deploy@<LAB_IP>:./handout/artifacts .
```