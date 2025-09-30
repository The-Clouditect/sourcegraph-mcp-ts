/**
 * Code Intelligence Service
 * 
 * Provides access to Sourcegraph's code intelligence APIs for features like:
 * - Definitions
 * - References
 * - Implementations
 * - Hover documentation
 * - Document symbols
 */

import axios from 'axios';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// API response type
export type CodeIntelligenceResponse = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

/**
 * Get Sourcegraph configuration from environment or provided config
 */
export const getSourcegraphConfig = (config?: { url?: string; token?: string }) => {
  const url = config?.url || process.env.SOURCEGRAPH_URL;
  const token = config?.token || process.env.SOURCEGRAPH_TOKEN;
  
  if (!url || !token) {
    throw new Error('Sourcegraph URL or token not configured. Please set SOURCEGRAPH_URL and SOURCEGRAPH_TOKEN environment variables.');
  }
  
  return { url, token };
};

/**
 * Execute a GraphQL query against the Sourcegraph API
 */
export async function executeSourcegraphQuery(
  graphqlQuery: string,
  variables: Record<string, any>,
  sourcegraphConfig?: {
    url?: string;
    token?: string;
  }
): Promise<any> {
  // Get configuration
  const config = getSourcegraphConfig(sourcegraphConfig);
  
  // Headers for Sourcegraph API
  const headers = {
    'Authorization': `token ${config.token}`,
    'Content-Type': 'application/json'
  };
  
  try {
    // Make the request to Sourcegraph API
    const response = await axios.post(
      `${config.url}/.api/graphql`,
      { query: graphqlQuery, variables },
      { headers }
    );
    
    return response.data;
  } catch (error: any) {
    // Format error for better debugging
    if (error.response) {
      throw new Error(`Sourcegraph API error (${error.response.status}): ${JSON.stringify(error.response.data)}`);
    } else if (error.request) {
      throw new Error(`No response from Sourcegraph API: ${error.message}`);
    } else {
      throw new Error(`Error setting up request: ${error.message}`);
    }
  }
}

/**
 * Get GraphQL query for definitions
 */
export function getDefinitionQuery() {
  return `
    query Definitions($repository: String!, $path: String!, $line: Int!, $character: Int!, $revision: String!) {
      repository(name: $repository) {
        commit(rev: $revision) {
          blob(path: $path) {
            lsif {
              definitions(line: $line, character: $character) {
                nodes {
                  resource {
                    path
                    repository {
                      name
                    }
                  }
                  range {
                    start {
                      line
                      character
                    }
                    end {
                      line
                      character
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  `;
}

/**
 * Get GraphQL query for references
 */
export function getReferencesQuery() {
  return `
    query References($repository: String!, $path: String!, $line: Int!, $character: Int!, $limit: Int!, $revision: String!) {
      repository(name: $repository) {
        commit(rev: $revision) {
          blob(path: $path) {
            lsif {
              references(line: $line, character: $character, first: $limit) {
                nodes {
                  resource {
                    path
                    repository {
                      name
                    }
                  }
                  range {
                    start {
                      line
                      character
                    }
                    end {
                      line
                      character
                    }
                  }
                }
                pageInfo {
                  hasNextPage
                }
              }
            }
          }
        }
      }
    }
  `;
}

/**
 * Get GraphQL query for implementations
 */
export function getImplementationsQuery() {
  return `
    query Implementations($repository: String!, $path: String!, $line: Int!, $character: Int!, $limit: Int!, $revision: String!) {
      repository(name: $repository) {
        commit(rev: $revision) {
          blob(path: $path) {
            lsif {
              implementations(line: $line, character: $character, first: $limit) {
                nodes {
                  resource {
                    path
                    repository {
                      name
                    }
                  }
                  range {
                    start {
                      line
                      character
                    }
                    end {
                      line
                      character
                    }
                  }
                }
                pageInfo {
                  hasNextPage
                }
              }
            }
          }
        }
      }
    }
  `;
}

/**
 * Get GraphQL query for hover documentation
 */
export function getHoverQuery() {
  return `
    query Hover($repository: String!, $path: String!, $line: Int!, $character: Int!, $revision: String!) {
      repository(name: $repository) {
        commit(rev: $revision) {
          blob(path: $path) {
            lsif {
              hover(line: $line, character: $character) {
                markdown {
                  text
                }
                range {
                  start {
                    line
                    character
                  }
                  end {
                    line
                    character
                  }
                }
              }
            }
          }
        }
      }
    }
  `;
}

/**
 * Get GraphQL query for document symbols (v6.7 using codeGraphData)
 */
export function getDocumentSymbolsQuery() {
  return `
    query DocumentSymbols($repository: String!, $path: String!, $revision: String!) {
      repository(name: $repository) {
        commit(rev: $revision) {
          blob(path: $path) {
            codeGraphData {
              occurrences(first: 1000) {
                nodes {
                  symbol
                  range {
                    start {
                      line
                      character
                    }
                    end {
                      line
                      character
                    }
                  }
                  roles
                }
              }
            }
          }
        }
      }
    }
  `;
}
/**
 * Format definitions results to readable output
 */
export function formatDefinitionResults(data: any): string {
  // Handle error cases
  if (!data?.repository?.commit?.blob?.lsif?.definitions?.nodes) {
    return "No definitions found or LSIF data not available for this file. LSIF data requires prior indexing.";
  }

  const nodes = data.repository.commit.blob.lsif.definitions.nodes;
  
  if (nodes.length === 0) {
    return "No definitions found for this symbol.";
  }

  let result = `## Definitions Found (${nodes.length})\n\n`;

  nodes.forEach((node: any, index: number) => {
    const repo = node.resource.repository.name;
    const path = node.resource.path;
    const startLine = node.range.start.line;
    const startChar = node.range.start.character;
    const endLine = node.range.end.line;
    const endChar = node.range.end.character;
    
    result += `### Definition ${index + 1}\n`;
    result += `**Location:** ${repo} - ${path}:${startLine + 1}:${startChar + 1}\n\n`;
    
    if (node.hover?.markdown?.text) {
      const docText = node.hover.markdown.text;
      result += `**Documentation:**\n${docText}\n\n`;
    }
  });

  return result;
}

/**
 * Format references results to readable output
 */
export function formatReferencesResults(data: any, params: { repository: string, path: string, line: number, character: number }): string {
  // Handle error cases
  if (!data?.repository?.commit?.blob?.lsif?.references?.nodes) {
    return "No references found or LSIF data not available for this file. LSIF data requires prior indexing.";
  }

  const references = data.repository.commit.blob.lsif.references;
  const nodes = references.nodes;
  const totalCount = references.nodes.length;  // Changed from pageInfo?.totalCount
  const hasMore = references.pageInfo.hasNextPage;
  
  if (nodes.length === 0) {
    return "No references found for this symbol.";
  }

  let result = `## References Found (${totalCount})\n\n`;
  result += `References to symbol at ${params.repository}:${params.path}:${params.line + 1}:${params.character + 1}\n\n`;

  // Group references by repository and file
  const groupedRefs: Record<string, Record<string, any[]>> = {};
  
  nodes.forEach((node: any) => {
    const repo = node.resource.repository.name;
    const path = node.resource.path;
    
    if (!groupedRefs[repo]) {
      groupedRefs[repo] = {};
    }
    
    if (!groupedRefs[repo][path]) {
      groupedRefs[repo][path] = [];
    }
    
    groupedRefs[repo][path].push(node);
  });

  // Format grouped references
  Object.keys(groupedRefs).forEach(repo => {
    result += `### Repository: ${repo}\n\n`;
    
    Object.keys(groupedRefs[repo]).forEach(path => {
      result += `#### File: ${path}\n\n`;
      
      groupedRefs[repo][path].forEach(ref => {
        const startLine = ref.range.start.line;
        const preview = ref.preview || "(no preview available)";
        
        result += `Line ${startLine + 1}: \`${escapeMarkdown(preview.trim())}\`\n\n`;
      });
    });
  });

  if (hasMore) {
    result += `\n> Note: There are more references available. This result is limited to showing ${nodes.length} references.\n`;
  }

  return result;
}

/**
 * Format implementations results to readable output
 */
export function formatImplementationsResults(data: any, params: { repository: string, path: string, line: number, character: number }): string {
  // Handle error cases
  if (!data?.repository?.commit?.blob?.lsif?.implementations?.nodes) {
    return "No implementations found or LSIF data not available for this file. LSIF data requires prior indexing.";
  }

  const implementations = data.repository.commit.blob.lsif.implementations;
  const nodes = implementations.nodes;
  const totalCount = implementations.nodes.length;  // Changed from pageInfo?.totalCount
  const hasMore = implementations.pageInfo.hasNextPage;
  
  if (nodes.length === 0) {
    return "No implementations found for this interface/abstract class.";
  }

  let result = `## Implementations Found (${totalCount})\n\n`;
  result += `Implementations of interface/class at ${params.repository}:${params.path}:${params.line + 1}:${params.character + 1}\n\n`;

  // Group implementations by repository and file
  const groupedImpls: Record<string, Record<string, any[]>> = {};
  
  nodes.forEach((node: any) => {
    const repo = node.resource.repository.name;
    const path = node.resource.path;
    
    if (!groupedImpls[repo]) {
      groupedImpls[repo] = {};
    }
    
    if (!groupedImpls[repo][path]) {
      groupedImpls[repo][path] = [];
    }
    
    groupedImpls[repo][path].push(node);
  });

  // Format grouped implementations
  Object.keys(groupedImpls).forEach(repo => {
    result += `### Repository: ${repo}\n\n`;
    
    Object.keys(groupedImpls[repo]).forEach(path => {
      result += `#### File: ${path}\n\n`;
      
      groupedImpls[repo][path].forEach(impl => {
        const startLine = impl.range.start.line;
        const preview = impl.preview || "(no preview available)";
        
        result += `Line ${startLine + 1}: \`${escapeMarkdown(preview.trim())}\`\n\n`;
      });
    });
  });

  if (hasMore) {
    result += `\n> Note: There are more implementations available. This result is limited to showing ${nodes.length} implementations.\n`;
  }

  return result;
}


/**
 * Format document symbols results to readable output
 */
export function formatDocumentSymbolsResults(data: any, params: { repository: string, path: string }): string {
  // Handle error cases
  if (!data?.repository?.commit?.blob?.codeGraphData?.[0]?.occurrences?.nodes) {
    return "No symbols found or LSIF data not available for this file. LSIF data requires prior indexing.";
  }

  const nodes = data.repository.commit.blob.codeGraphData[0].occurrences.nodes;
  
  // Filter for definitions only
  const definitions = nodes.filter((node: any) => 
    node.roles && node.roles.includes("DEFINITION")
  );
  
  if (definitions.length === 0) {
    return "No symbol definitions found in this file.";
  }

  // Parse and categorize symbols
  const symbols = definitions.map((node: any) => {
    const symbolStr = node.symbol;
    let name = symbolStr;
    let kind = 'Variable';
    
    // Extract name from SCIP format
    // Format: "scip-go gomod github.com/... `package`/SymbolName#"
    const backtickMatch = symbolStr.match(/`[^`]+`\/([^#.()]+)(#|\.|\(\)\.)?/);
    if (backtickMatch) {
      name = backtickMatch[1];
      // Determine kind based on suffix
      const suffix = backtickMatch[2];
      if (suffix === '#') kind = 'Class';
      else if (suffix === '().') kind = 'Function';
      else if (suffix === '.') kind = 'Property';
    } else {
      // Fallback: try to extract from local symbols
      const localMatch = symbolStr.match(/^local\s+\d+$/);
      if (localMatch) {
        name = symbolStr;
        kind = 'Variable';
      }
    }
    
    return {
      name,
      kind,
      line: node.range.start.line
    };
  });

  // Group by kind
  const grouped: Record<string, any[]> = {};
  symbols.forEach((sym: any) => {
    const category = sym.kind === 'Class' ? 'Classes/Interfaces' :
                     sym.kind === 'Function' ? 'Functions/Methods' :
                     'Variables/Properties';
    
    if (!grouped[category]) {
      grouped[category] = [];
    }
    grouped[category].push(sym);
  });

  // Format output
  let result = `## Document Symbols\n\n`;
  result += `Found ${symbols.length} symbols in ${params.path}\n\n`;

  Object.keys(grouped).sort().forEach(category => {
    result += `### ${category}\n`;
    grouped[category]
      .sort((a: any, b: any) => a.line - b.line)
      .forEach((sym: any) => {
        result += `- ${sym.name} (line ${sym.line + 1})\n`;
      });
    result += `\n`;
  });

  return result;
}

/**
 * Escape markdown special characters in text
 */
function escapeMarkdown(text: string): string {
  return text
    .replace(/\*/g, '\\*')
    .replace(/\_/g, '\\_')
    .replace(/\~/g, '\\~')
    .replace(/\`/g, '\\`');
}