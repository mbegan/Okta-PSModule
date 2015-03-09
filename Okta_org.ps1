[Boolean]$oktaVerbose = $true
[String]$oktaDefOrg = "prod"

[Hashtable]$oktaOrgs = @{
                        prod = [Hashtable]@{
                                            baseUrl  = [String]"https://yourdomain.okta.com"
                                            secToken = [String]"SomethingYoushouldntSharewiththeworld"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        prev = [HashTable]@{
                                            baseUrl  = [String]"https://yourdomain.oktapreview.com"
                                            secToken = [String]"Keepthistoyourself"
                                            enablePagination = [boolean]$true
                                            pageSize = [int]500
                                           }
                        }
