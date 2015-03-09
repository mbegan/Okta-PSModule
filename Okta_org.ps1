[Boolean]$oktaVerbose = $true
[String]$oktaDefOrg = "prod"

[Hashtable]$oktaOrgs = @{
                        prod = [Hashtable]@{
                                            baseUrl  = [String]"https://varian.okta.com"
                                            secToken = [String]"YourAPIToken"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        prev = [HashTable]@{
                                            baseUrl  = [String]"https://varian.oktapreview.com"
                                            secToken = [String]"YourAPIToken"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        }
                        
