<#
    Keep 

#>

[Boolean]$oktaVerbose = $true
[String]$oktaDefOrg = "prod"

[Hashtable]$oktaOrgs = @{
                        prod = [Hashtable]@{
                                            baseUrl  = [String]"https://varian.okta.com"
                                            secToken = [String]"00RvYIddyM2DzE9oFLF_HuJxwrrvHUvKiZ48-Si7WI"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        prev = [HashTable]@{
                                            baseUrl  = [String]"https://varian.oktapreview.com"
                                            secToken = [String]"00Sq8dDiRy33EsfHNMbY2_RoLc1_T0AeLPjcnG_35p"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        Aprev = [HashTable]@{
                                            baseUrl  = [String]"https://varian-admin.oktapreview.com"
                                            secToken = [String]"00Sq8dDiRy33EsfHNMbY2_RoLc1_T0AeLPjcnG_35p"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        }