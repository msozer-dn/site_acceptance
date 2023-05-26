class Filters():
    def __init__(self) -> None:
      self.filter_backbone_reach='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
                  <ncp>
                    <oper-items>
                      <backplane-reachability-statistics xmlns="http://drivenets.com/ns/yang/dn-sys-backplane">
                        <neighbor-node>
                          <neighbor-node-name/>
                          <current-reachable-active-lanes/>
                        </neighbor-node>
                      </backplane-reachability-statistics>
                    </oper-items>
                  </ncp>
                </ncps>
              </system>
            </drivenets-top>'''

      self.system_management='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <management-route xmlns="http://drivenets.com/ns/yang/dn-oob-mgmt-route"/>
              </system>
            </drivenets-top>'''


      self.filter_ncm='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <interfaces xmlns="http://drivenets.com/ns/yang/dn-interfaces">
                <interface>
                  <name>ctrl-ncm-B0/16</name>
                  <ncm-interfaces>
                    <oper-items>
                      <expected-neighbor-interface xmlns="http://drivenets.com/ns/yang/dn-sys-backplane"/>
                      <actual-neighbor-interface xmlns="http://drivenets.com/ns/yang/dn-sys-backplane"/>
                      <connection-state xmlns="http://drivenets.com/ns/yang/dn-sys-backplane"/>
                      <actual-neighbor-serial-number xmlns="http://drivenets.com/ns/yang/dn-sys-backplane"/>
                    </oper-items>
                  </ncm-interfaces>
                </interface>
              </interfaces>
            </drivenets-top>
            '''

      self.filter_power='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
                  <ncp>
                    <config-items>
                      <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                        <power-supply-units>
                          <oper-items>
                            <psu>
                              <psu-id/>
                              <present/>
                              <status/>
                              <uptime/>
                            </psu>
                          </oper-items>
                        </power-supply-units>
                      </platform>
                    </config-items>
                  </ncp>
                </ncps>
              </system>
            </drivenets-top>
            '''

      self.filter_power='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
                  <ncp>
                    <config-items>
                      <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                        <power-supply-units>
                          <oper-items>
                            <psu>
                              <psu-id/>
                              <present/>
                              <status/>
                              <uptime/>
                            </psu>
                          </oper-items>
                        </power-supply-units>
                      </platform>
                    </config-items>
                  </ncp>
                </ncps>
              </system>
            </drivenets-top>
            '''


      self.filter_backbone_reach='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
                  <ncp>
                    <oper-items>
                      <backplane-reachability-statistics xmlns="http://drivenets.com/ns/yang/dn-sys-backplane">
                        <neighbor-node>
                          <neighbor-node-name/>
                          <current-reachable-active-lanes/>
                        </neighbor-node>
                      </backplane-reachability-statistics>
                    </oper-items>
                  </ncp>
                </ncps>
              </system>
            </drivenets-top>'''

      self.filter_cluster_version='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <oper-items>
            <name/>
            <system-type/>
            <system-version/>
            <oper-status/>
          </oper-items>
        </system>
      </drivenets-top> '''

      self.filter_ncp_connectivity='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
                  <ncp>
                    <oper-items>
                      <ncp-id/>
                      <model/>
                      <admin-state/>
                      <oper-status/>
                    </oper-items>
                  </ncp>
                </ncps>
              </system>
            </drivenets-top>'''

      self.filter_ncf_connectivity='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
                  <ncf>
                    <oper-items>
                      <ncf-id/>
                      <model/>
                      <admin-state/>
                      <oper-status/>
                    </oper-items>
                  </ncf>
                </ncfs>
              </system>
            </drivenets-top>'''

      self.filter_ncc_connectivity='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncc">
                  <ncc>
                    <oper-items>
                      <ncc-id/>
                      <oper-status/>
                    </oper-items>
                  </ncc>
                </nccs>
              </system>
            </drivenets-top>'''

      self.filter_ncm_connectivity='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
              <system xmlns="http://drivenets.com/ns/yang/dn-system">
                <ncms xmlns="http://drivenets.com/ns/yang/dn-sys-ncm">
                  <ncm>
                    <oper-items>
                      <ncm-id/>
                      <oper-status/>
                    </oper-items>
                  </ncm>
                </ncms>
              </system>
            </drivenets-top>'''

      self.filter_ncp_fabric_connection='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
  <system xmlns="http://drivenets.com/ns/yang/dn-system">
    <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
      <ncp>
        <oper-items>
          <backplane-statistics xmlns="http://drivenets.com/ns/yang/dn-sys-backplane">
            <current-connected-fabric-interfaces/>
          </backplane-statistics>
        </oper-items>
      </ncp>
    </ncps>
  </system>
</drivenets-top>'''

      self.filter_ncp_active_lanes='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
  <system xmlns="http://drivenets.com/ns/yang/dn-system">
    <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
      <ncp>
        <oper-items>
          <backplane-reachability-statistics xmlns="http://drivenets.com/ns/yang/dn-sys-backplane">
            <neighbor-node/>
          </backplane-reachability-statistics>
        </oper-items>
      </ncp>
    </ncps>
  </system>
</drivenets-top>'''

      self.filter_oob_mgmt='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <management-route xmlns="http://drivenets.com/ns/yang/dn-oob-mgmt-route"/>
        </system>
      </drivenets-top>'''

      self.site_mgmt_ip= {'sn00.ams00':'10.254.54.20/25',
                          'sn00.atl00':'10.254.2.20/25',
                          'sn00.chi00':'10.254.6.20/25',
                          'sn00.dfw00':'10.254.0.20/25',
                          'sn00.dtw00':'10.254.18.20/25',
                          'sn00.ewr00':'10.254.10.20/25',
                          'sn00.fra00':'10.254.50.20/25',
                          'sn00.lax00':'10.254.4.20/25',
                          'sn00.lon00':'10.254.52.20/25',
                          'sn00.mia00':'10.254.16.20/25',
                          'sn00.osa00':'10.254.82.20/25',
                          'sn00.par00':'10.254.58.20/25',
                          'sn00.phx00':'10.254.20.20/25',
                          'sn00.sat00':'10.254.22.20/25',
                          'sn00.sea00':'10.254.14.20/25',
                          'sn00.sfo00':'10.254.8.20/25',
                          'sn00.sto00':'10.254.56.20/25',
                          'sn00.tyo00':'10.254.80.20/25',
                          'sn00.was00':'10.254.12.20/25',
                          'sn00.yto00':'10.254.26.20/25',
                          'sn01.atl00':'10.254.3.20/25',
                          'sn01.chi00':'10.254.7.20/25',
                          'sn01.dfw00':'10.254.1.20/25',
                          'sn01.dtw00':'10.254.19.20/25',
                          'sn01.ewr00':'10.254.11.20/25',
                          'sn01.lax00':'10.254.5.20/25',
                          'sn01.mia00':'10.254.17.20/25',
                          'sn01.phx00':'10.254.21.20/25',
                          'sn01.sat00':'10.254.23.20/25',
                          'sn01.sea00':'10.254.15.20/25',
                          'sn01.sfo00':'10.254.9.20/25',
                          'sn01.was00':'10.254.13.20/25',
                          'dal00': "10.255.250.20/25"}

      self.filter_oob_mgmt='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <management-route xmlns="http://drivenets.com/ns/yang/dn-oob-mgmt-route"/>
        </system>
      </drivenets-top>'''

      self.filter_ncc_psu='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncc">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <power-supply-units>
                    <oper-items>
                      <psu>
                        <status/>
                      </psu>
                    </oper-items>
                  </power-supply-units>
                </platform>
              </config-items>
            </ncc>
          </nccs>
        </system>
      </drivenets-top>
      '''

      self.filter_ncp_psu='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <power-supply-units>
                    <oper-items>
                      <psu>
                        <status/>
                      </psu>
                    </oper-items>
                  </power-supply-units>
                </platform>
              </config-items>
            </ncp>
          </ncps>
        </system>
      </drivenets-top>'''

      self.filter_ncm_psu='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncms xmlns="http://drivenets.com/ns/yang/dn-sys-ncm">
            <ncm>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <power-supply-units>
                    <oper-items>
                      <psu>
                        <status/>
                      </psu>
                    </oper-items>
                  </power-supply-units>
                </platform>
              </config-items>
            </ncm>
          </ncms>
        </system>
      </drivenets-top>
      '''

      self.filter_ncf_psu='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <power-supply-units>
                    <oper-items>
                      <psu>
                        <status/>
                      </psu>
                    </oper-items>
                  </power-supply-units>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
        </system>
      </drivenets-top>
      '''

      self.filter_all_psu='''
            <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <power-supply-units>
                    <oper-items>
                      <psu>
                        <status/>
                      </psu>
                    </oper-items>
                  </power-supply-units>
                </platform>
              </config-items>
            </ncp>
          </ncps>
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <power-supply-units>
                    <oper-items>
                      <psu>
                        <status/>
                      </psu>
                    </oper-items>
                  </power-supply-units>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncc">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <power-supply-units>
                    <oper-items>
                      <psu>
                        <status/>
                      </psu>
                    </oper-items>
                  </power-supply-units>
                </platform>
              </config-items>
            </ncc>
          </nccs>
        </system>
      </drivenets-top>'''

      self.filter_ncp_fan='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <fans>
                    <oper-items>
                      <fan/>
                    </oper-items>
                  </fans>
                </platform>
              </config-items>
            </ncp>
          </ncps>
        </system>
      </drivenets-top>'''

      self.filter_ncc_fan='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncc">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <fans>
                    <oper-items>
                      <fan/>
                    </oper-items>
                  </fans>
                </platform>
              </config-items>
            </ncc>
          </nccs>
        </system>
      </drivenets-top>'''

      self.filter_ncf_fan='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <fans>
                    <oper-items>
                      <fan/>
                    </oper-items>
                  </fans>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
        </system>
      </drivenets-top>'''

      self.filter_ncm_fan='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncms xmlns="http://drivenets.com/ns/yang/dn-sys-ncm">
            <ncm>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <fans>
                    <oper-items>
                      <fan/>
                    </oper-items>
                  </fans>
                </platform>
              </config-items>
            </ncm>
          </ncms>
        </system>
      </drivenets-top>'''


      self.filter_hw_temp='''
 <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <temperature-sensors>
                    <oper-items>
                      <temperature-sensor/>
                    </oper-items>
                  </temperature-sensors>
                </platform>
              </config-items>
            </ncp>
          </ncps>
        </system>
      </drivenets-top>'''

      self.filter_ncp_ncf_ncm_cpld='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <cpld-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncp>
          </ncps>
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <cpld-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
          <ncms xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncm>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <cpld-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncm>
          </ncms>
        </system>
      </drivenets-top>'''

      self.filter_onie_version='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <onie-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncp>
          </ncps>
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <onie-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
          <ncms xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncm>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <onie-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncm>
          </ncms>
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <onie-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncc>
          </nccs>
        </system>
      </drivenets-top>'''

      self.filter_bios='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <bios-version/>
                    <bios-mode/>
                  </oper-items>
                </platform>
              </config-items>
            </ncp>
          </ncps>
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <bios-version/>
                    <bios-mode/>
                  </oper-items>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
          <ncms xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncm>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <bios-version/>
                    <bios-mode/>
                  </oper-items>
                </platform>
              </config-items>
            </ncm>
          </ncms>
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <bios-version/>
                    <bios-mode/>
                  </oper-items>
                </platform>
              </config-items>
            </ncc>
          </nccs>
        </system>
      </drivenets-top>'''

      self.filter_base_os='''
          <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <host-os/>
                  </oper-items>
                </platform>
              </config-items>
            </ncp>
          </ncps>
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <host-os/>
                  </oper-items>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncc">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <host-os/>
                  </oper-items>
                </platform>
              </config-items>
            </ncc>
          </nccs>
        </system>
      </drivenets-top>'''

      self.filter_hw_revision_ncp_ncf='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <ncps xmlns="http://drivenets.com/ns/yang/dn-sys-ncp">
            <ncp>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <hardware-revision/>
                  </oper-items>
                </platform>
              </config-items>
            </ncp>
          </ncps>
          <ncfs xmlns="http://drivenets.com/ns/yang/dn-sys-ncf">
            <ncf>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <hardware-revision/>
                  </oper-items>
                </platform>
              </config-items>
            </ncf>
          </ncfs>
        </system>
      </drivenets-top>'''

      self.filter_ncm_ncc_ipmi='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncc">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <ipmi-version>
                      <image-1-version/>
                      <image-2-version/>
                    </ipmi-version>
                  </oper-items>
                </platform>
              </config-items>
            </ncc>
          </nccs>
          <ncms xmlns="http://drivenets.com/ns/yang/dn-sys-ncm">
            <ncm>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <ipmi-version>
                      <image-1-version/>
                      <image-2-version/>
                    </ipmi-version>
                  </oper-items>
                </platform>
              </config-items>
            </ncm>
          </ncms>
        </system>
      </drivenets-top>'''

      self.filter_eth_controller='''<drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <nccs xmlns="http://drivenets.com/ns/yang/dn-sys-ncc">
            <ncc>
              <config-items>
                <platform xmlns="http://drivenets.com/ns/yang/dn-platform">
                  <oper-items>
                    <on-board-management-ethernet-controller-version/>
                  </oper-items>
                </platform>
              </config-items>
            </ncc>
          </nccs>
        </system>
      </drivenets-top>'''

      self.filter_vrf_route_summary_vADI='''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <network-services xmlns="http://drivenets.com/ns/yang/dn-network-services">
          <vrfs xmlns="http://drivenets.com/ns/yang/dn-vrf">
            <vrf>
              <vrf-name>ISP_ADI</vrf-name>
              <oper-items>
                <vrf-name>ISP_ADI</vrf-name>
                <oper-status>up</oper-status>
                <vrf-route-summary>
                  <ipv4-unicast-routes>
                    <ebgp-routes/>
                  </ipv4-unicast-routes>
                  <ipv6-unicast-routes>
                    <ebgp-routes/>
                  </ipv6-unicast-routes>
                </vrf-route-summary>
              </oper-items>
              <vrf-name/>
            </vrf>
          </vrfs>
        </network-services>
      </drivenets-top>  '''

      self.filter_number_of_bgp_nb_vADI='''
            <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <network-services xmlns="http://drivenets.com/ns/yang/dn-network-services">
          <vrfs xmlns="http://drivenets.com/ns/yang/dn-vrf">
            <vrf>
              <vrf-name>ISP_ADI</vrf-name>
              <protocols>
                <bgp xmlns="http://drivenets.com/ns/yang/dn-bgp">
                  <global>
                    <global-oper>
                      <bgp-summary>
                        <global>
                          <address-families>
                            <address-family>
                            </address-family>
                          </address-families>
                        </global>
                      </bgp-summary>
                    </global-oper>
                  </global>
                </bgp>
              </protocols>
              <vrf-name/>
            </vrf>
          </vrfs>
        </network-services>
      </drivenets-top>
      '''

      self.filter_system_name='''
            <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <system xmlns="http://drivenets.com/ns/yang/dn-system">
          <config-items>
            <name/>
          </config-items>
        </system>
      </drivenets-top>
      '''

    def filter_backbone_control_connections(self,interface):
      rpc=f'''
      <drivenets-top xmlns="http://drivenets.com/ns/yang/dn-top">
        <interfaces xmlns="http://drivenets.com/ns/yang/dn-interfaces">
          <interface>
            <name>{interface}</name>
            <ncm-interfaces>
              <oper-items>
                <expected-neighbor-interface xmlns="http://drivenets.com/ns/yang/dn-sys-backplane"/>
                <actual-neighbor-interface xmlns="http://drivenets.com/ns/yang/dn-sys-backplane"/>
                <connection-state xmlns="http://drivenets.com/ns/yang/dn-sys-backplane">ok</connection-state>
                <actual-neighbor-serial-number xmlns="http://drivenets.com/ns/yang/dn-sys-backplane"/>
              </oper-items>
            </ncm-interfaces>
          </interface>
        </interfaces>
      </drivenets-top>'''
      return rpc

