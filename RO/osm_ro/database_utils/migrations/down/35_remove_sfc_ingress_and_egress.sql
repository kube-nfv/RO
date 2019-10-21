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
-- Removing ingress and egress ports for SFC purposes.
-- Inserting only one port for ingress and egress.
--

ALTER TABLE sce_rsp_hops
  DROP FOREIGN KEY FK_interfaces_rsp_hop_ingress,
  CHANGE COLUMN ingress_interface_id interface_id VARCHAR(36) NOT NULL
    AFTER if_order,
  ADD CONSTRAINT FK_interfaces_rsp_hop
    FOREIGN KEY (interface_id)
    REFERENCES interfaces (uuid) ON UPDATE CASCADE ON DELETE CASCADE,
  DROP FOREIGN KEY FK_interfaces_rsp_hop_egress,
  DROP COLUMN egress_interface_id;

DELETE FROM schema_version WHERE version_int='35';
