[Boolean]$oktaVerbose = $true
[String]$oktaDefOrg = "prod"

[Hashtable]$oktaOrgs = @{
                        prod = [Hashtable]@{
                                            baseUrl  = [String]"https://varian.okta.com"
                                            secToken = [String]""
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        prev = [HashTable]@{
                                            baseUrl  = [String]"https://varian.oktapreview.com"
                                            secToken = [String]""
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        Aprev = [HashTable]@{
                                            baseUrl  = [String]"https://varian-admin.oktapreview.com"
                                            secToken = [String]"xxx"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        }