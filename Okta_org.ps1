[Boolean]$oktaVerbose = $true
[String]$oktaDefOrg = "prod"

[Hashtable]$oktaOrgs = @{
                        prod = [Hashtable]@{
                                            baseUrl  = [String]"https://YourDomain.okta.com"
                                            secToken = [String]"YourAPIToken"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        prev = [HashTable]@{
                                            baseUrl  = [String]"https://YourDomain.oktapreview.com"
                                            secToken = [String]"YourAPIToken"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        }