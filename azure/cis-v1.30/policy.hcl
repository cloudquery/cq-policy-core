policy "cis-v1.30" {
  description = "Azure CIS V1.30 Policy"
  configuration {
    provider "azure" {
      version = ">= 0.2.4"
    }
  }

  policy "aws-cis-section-1" {
    description = "Azure CIS Section 1"

  }

  policy "aws-cis-section-2" {
    description = "Azure CIS Section 2"

  }

  policy "aws-cis-section-3" {
    description = "Azure CIS Section 3"

  }

  policy "aws-cis-section-4" {
    description = "Azure CIS Section 4"

  }

  policy "aws-cis-section-5" {
    description = "Azure CIS Section 5"

  }

  policy "aws-cis-section-6" {
    description = "Azure CIS Section 6"

  }

  policy "aws-cis-section-7" {
    description = "Azure CIS Section 7"

    query "7.1" {
      description = "Azure CIS 7.1 Ensure Virtual Machines are utilizing Managed Disks (Manual)"
      query = <<EOF
      SELECT subscription_id , id, name
      FROM azure_compute_virtual_machines WHERE storage_profile -> 'osDisk' -> 'managedDisk' -> 'id' IS NULL;
    EOF
    }

    query "7.2" {
      description = "Azure CIS 7.2 Ensure that 'OS and Data' disks are encrypted with CMK (Automated)"
      query = <<EOF
      SELECT v.id AS vm_id , v.name AS vm_name, d.id AS disk_id , d.name AS disk_name, d.encryption_type
      FROM azure_compute_virtual_machines v
      JOIN azure_compute_disks d ON
      LOWER(v.id) = LOWER(d.managed_by)
      AND encryption_type NOT LIKE '%CustomerKey%';
    EOF
    }

    query "7.3" {
      description = "Azure CIS 7.3 Ensure that 'Unattached disks' are encrypted with CMK (Automated)"
      //todo maybe replace '%CustomerKey%' with 'EncryptionAtRestWithCustomerKey'
      query = <<EOF
      SELECT subscription_id, id AS disk_id, "name" AS disk_name, encryption_type
      FROM azure_compute_disks acd3
      WHERE disk_state = 'Unattached'
      AND encryption_type NOT LIKE '%CustomerKey%';
    EOF
    }

    query "7.4" {
      description = "Azure CIS 7.4 Ensure that only approved extensions are installed (Manual)"
      //todo we can list machines extensions names to ease manual check
      query = <<EOF
      SELECT v.id AS vm_id , v.name AS vm_name, r."name" AS extension_name
      FROM azure_compute_virtual_machines v
      JOIN azure_compute_virtual_machine_resources r ON
      v.cq_id = r.virtual_machine_cq_id
    EOF
    }


    query "7.5" {
      description = "Azure CIS 7.5 Ensure that the latest OS Patches for all Virtual Machines are applied (Manual)"
      query = file("queries/manual.sql")
    }


    query "7.6" {
      description = "Azure CIS 7.6 Ensure that the endpoint protection for all Virtual Machines is installed (Manual)"
      //todo theoretically we can check if vm has security extensions
      //      EndpointSecurity || TrendMicroDSA* || Antimalware || EndpointProtection || SCWPAgent || PortalProtectExtension* || FileSecurity*
      query = file("queries/manual.sql")
    }

    query "7.7" {
      description = "Azure CIS 7.7 Ensure that VHD's are encrypted (Manual)"
      query = <<EOF
      WITH vm_disks AS ( SELECT subscription_id , id, name, jsonb_array_elements( instance_view -> 'disks') AS disk
      FROM azure_compute_virtual_machines), disk_encrytpions AS ( SELECT subscription_id , id, name, disk -> 'name' AS disk_name , (disk -> 'encryptionSettings' -> 0 ->> 'enabled')::boolean AS encryption_enabled
      FROM vm_disks ) SELECT *
      FROM disk_encrytpions
      WHERE encryption_enabled IS NULL
      OR encryption_enabled != TRUE;
    EOF
    }
  }

  policy "aws-cis-section-8" {
    description = "Azure CIS Section 8"

  }


  policy "aws-cis-section-9" {
    description = "Azure CIS Section 9"

  }
}