/**
 * Copyright (c) 2023-2024, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// eslint-disable-next-line no-restricted-imports
import { Theme } from "@oxygen-ui/react";
import { extendTheme } from "@oxygen-ui/react/theme";

export const AsgardeoTheme: Theme = extendTheme({
    colorSchemes: {
        dark: {
            palette: {
                customComponents: {
                    Navbar: {
                        collapsibleItemBackground: "#E7E4E2"
                    }
                },
                gradients: {
                    primary: {
                        stop1: "#EB4F63",
                        stop2: "#FA7B3F"
                    }
                },
                primary: {
                    main: "#ff9"
                }
            }
        },
        light: {
            palette: {
                customComponents: {
                    AppShell: {
                        Main: {
                            background: "#D4F1F4"
                        },
                        MainWrapper: {
                            background: "#75E6DA"
                        }
                    },
                    Navbar: {
                        background: "#94C973",
                        collapsibleItemBackground: "#18A558"
                    }
                },
                gradients: {
                    primary: {
                        stop1: "#0000FF",
                        stop2: "#2E8BC0"
                    }
                },
                primary: {
                    main: "#31ED31"
                },

            }
        }
    },
    components: {
        MuiAppBar: {
            styleOverrides: {
                root: {
                    backgroundColor: "#929EAD",
                    borderBottom: "none"
                }
            }
        },
        MuiChip: {
            styleOverrides: {
                root: {
                    fontSize: "0.6125rem",
                    height: "20px"
                }
            }
        },
        MuiDrawer: {
            styleOverrides: {
                paper: {
                    borderRight: "none",
                    boxShadow: "none"
                }
            }
        },
        MuiMenu: {
            styleOverrides: {
                paper: {
                    border: "1px solid rgba(0, 0, 0, 0.08)",
                    borderRadius: "8px",
                    boxShadow: "0px 2px 4px rgba(0, 0, 0, 0.08)"
                }
            }
        },
        MuiOutlinedInput: {
            styleOverrides: {
                input: {
                    padding: "0.67857143em 1em"
                },
                root: {
                    fontFamily: "Cedarville Cursive, cursive"
                }
            }
        },
        MuiButton: {
            styleOverrides: {
                root: {
                    backgroundColor: "#8B0000", // Deep red background color for buttons
                    color: "white", // Text color for buttons to ensure readability
                    "&:hover": {
                        backgroundColor: "#640000" // Slightly darker red on hover for visual feedback
                    }
                }
            }
        }
    },

    customComponents: {
        AppShell: {
            properties: {
                mainBorderTopLeftRadius: "24px",
                navBarTopPosition: "80px"
            }
        },
        Navbar: {
            properties: {
                "chip-background-color": "#8A8AFF",
                "chip-color": "var(--oxygen-palette-primary-contrastText)"
            }
        }
    },
    shape: {
        borderRadius: 8
    },
    typography: {
        fontFamily: "Cedarville Cursive, cursive",
        h1: {
            fontWeight: 1200
        }
    }
});
