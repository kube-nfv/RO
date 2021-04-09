/**
* Licensed under the Apache License, Version 2.0 (the "License"); you may
* not use this file except in compliance with the License. You may obtain
* a copy of the License at
*
*         http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
* License for the specific language governing permissions and limitations
* under the License.
**/
--
-- Tear down database structure required for integrating OSM with
-- Wide Are Network Infrastructure Managers
--

DROP TABLE IF EXISTS wim_port_mappings;
DROP TABLE IF EXISTS wim_nfvo_tenants;
DROP TABLE IF EXISTS instance_wim_nets;

ALTER TABLE `vim_wim_actions` DROP FOREIGN KEY `FK_actions_wims`;
ALTER TABLE `vim_wim_actions` DROP INDEX `FK_actions_wims`;
ALTER TABLE `vim_wim_actions` DROP INDEX `item_type_id`;
ALTER TABLE `vim_wim_actions` MODIFY `item` enum(
  'datacenters_flavors',
  'datacenter_images',
  'instance_nets',
  'instance_vms',
  'instance_interfaces',
  'instance_sfis',
  'instance_sfs',
  'instance_classifications',
  'instance_sfps') NOT NULL
  COMMENT 'table where the item is stored';
ALTER TABLE `vim_wim_actions` MODIFY `datacenter_vim_id` varchar(36) NOT NULL;
ALTER TABLE `vim_wim_actions` DROP `wim_internal_id`, DROP `wim_account_id`;
ALTER TABLE `vim_wim_actions` RENAME TO `vim_actions`;

DROP TABLE IF EXISTS wim_accounts;
DROP TABLE IF EXISTS wims;

DELETE FROM schema_version WHERE version_int='34';
