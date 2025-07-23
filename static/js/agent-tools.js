
let tools = [];
let commandCounter = 1;

// Load tools on page load
document.addEventListener('DOMContentLoaded', function() {
    loadTools();
});

function loadTools() {
    fetch('/api/agent-tools')
        .then(response => response.json())
        .then(data => {
            tools = data.tools || [];
            renderTools();
        })
        .catch(error => {
            console.error('Error loading tools:', error);
        });
}

function renderTools() {
    const container = document.getElementById('toolsList');
    
    if (tools.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 3rem; color: #6b7280;">
                <i class="fas fa-tools" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                <h3>No tools created yet</h3>
                <p>Create your first agent tool to get started</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = tools.map(tool => `
        <div class="tool-card">
            <div class="tool-header">
                <div>
                    <h3 style="margin: 0; color: #1a202c;">${tool.name}</h3>
                    <p style="margin: 0.25rem 0 0 0; color: #6b7280;">${tool.description || 'No description'}</p>
                </div>
                <div style="display: flex; gap: 1rem; align-items: center;">
                    <span class="tool-status status-${tool.status || 'idle'}">${(tool.status || 'idle').toUpperCase()}</span>
                    <button onclick="runTool('${tool.id}')" class="btn-primary" ${tool.status === 'running' ? 'disabled' : ''}>
                        <i class="fas fa-play"></i> Run
                    </button>
                    <button onclick="editTool('${tool.id}')" class="btn-secondary">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button onclick="deleteTool('${tool.id}')" class="btn-danger">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            
            <div style="margin-top: 1rem;">
                <h4 style="margin: 0 0 0.5rem 0; color: #374151;">Commands (${tool.commands.length})</h4>
                ${tool.commands.map((cmd, index) => `
                    <div class="command-step">
                        <div class="step-number">${index + 1}</div>
                        <code style="margin-top: 1rem; display: block;">${cmd}</code>
                    </div>
                `).join('')}
            </div>
            
            ${tool.lastExecution ? `
                <div style="margin-top: 1rem;">
                    <h4 style="margin: 0 0 0.5rem 0; color: #374151;">Last Execution Output</h4>
                    <div class="command-output">${tool.lastExecution.output || 'No output'}</div>
                    <small style="color: #6b7280;">Executed ${new Date(tool.lastExecution.timestamp).toLocaleString()}</small>
                </div>
            ` : ''}
        </div>
    `).join('');
}

function openToolBuilder() {
    document.getElementById('toolBuilderModal').style.display = 'block';
    resetForm();
}

function closeToolBuilder() {
    document.getElementById('toolBuilderModal').style.display = 'none';
}

function resetForm() {
    document.getElementById('toolForm').reset();
    document.getElementById('commandsContainer').innerHTML = `
        <div class="command-step">
            <div class="step-number">1</div>
            <input type="text" class="form-input" placeholder="Enter command (e.g., git clone {repo_url})" style="margin-top: 1rem;">
            <button type="button" onclick="removeCommand(this)" class="btn-danger" style="margin-top: 0.5rem; float: right;">Remove</button>
        </div>
    `;
    document.getElementById('variablesContainer').innerHTML = `
        <div style="display: flex; gap: 1rem; margin-bottom: 0.5rem;">
            <input type="text" class="form-input" placeholder="Variable name (e.g., repo_url)" style="flex: 1;">
            <input type="text" class="form-input" placeholder="Description" style="flex: 2;">
            <button type="button" onclick="removeVariable(this)" class="btn-danger">Remove</button>
        </div>
    `;
    commandCounter = 1;
}

function addCommand() {
    commandCounter++;
    const container = document.getElementById('commandsContainer');
    const commandDiv = document.createElement('div');
    commandDiv.className = 'command-step';
    commandDiv.innerHTML = `
        <div class="step-number">${commandCounter}</div>
        <input type="text" class="form-input" placeholder="Enter command" style="margin-top: 1rem;">
        <button type="button" onclick="removeCommand(this)" class="btn-danger" style="margin-top: 0.5rem; float: right;">Remove</button>
    `;
    container.appendChild(commandDiv);
}

function removeCommand(button) {
    const commandDiv = button.closest('.command-step');
    commandDiv.remove();
    updateCommandNumbers();
}

function updateCommandNumbers() {
    const commands = document.querySelectorAll('#commandsContainer .command-step');
    commands.forEach((cmd, index) => {
        cmd.querySelector('.step-number').textContent = index + 1;
    });
    commandCounter = commands.length;
}

function addVariable() {
    const container = document.getElementById('variablesContainer');
    const variableDiv = document.createElement('div');
    variableDiv.style.cssText = 'display: flex; gap: 1rem; margin-bottom: 0.5rem;';
    variableDiv.innerHTML = `
        <input type="text" class="form-input" placeholder="Variable name" style="flex: 1;">
        <input type="text" class="form-input" placeholder="Description" style="flex: 2;">
        <button type="button" onclick="removeVariable(this)" class="btn-danger">Remove</button>
    `;
    container.appendChild(variableDiv);
}

function removeVariable(button) {
    button.closest('div').remove();
}

function createFromTemplate(templateType) {
    const templates = {
        'git-clone': {
            name: 'Git Repository Analyzer',
            description: 'Clone a repository and analyze its structure and files',
            commands: [
                'git clone {repo_url} {project_name}',
                'cd {project_name}',
                'find . -type f -name "*.py" -o -name "*.js" -o -name "*.html" | head -20',
                'wc -l $(find . -type f -name "*.py" -o -name "*.js") 2>/dev/null || echo "No code files found"'
            ],
            variables: [
                { name: 'repo_url', description: 'Git repository URL to clone' },
                { name: 'project_name', description: 'Local directory name for the project' }
            ]
        },
        'web-scrape': {
            name: 'Web Scraper & Analyzer',
            description: 'Fetch web content and analyze it',
            commands: [
                'curl -s "{url}" > webpage.html',
                'grep -o "<title>[^<]*" webpage.html | sed "s/<title>//"',
                'grep -c "<a href" webpage.html',
                'head -20 webpage.html'
            ],
            variables: [
                { name: 'url', description: 'URL to scrape and analyze' }
            ]
        },
        'file-analysis': {
            name: 'File Structure Analyzer',
            description: 'Analyze file structure and content of a directory',
            commands: [
                'cd {directory}',
                'find . -type f | wc -l',
                'du -sh .',
                'find . -name "*.{extension}" -exec wc -l {} + 2>/dev/null | tail -1'
            ],
            variables: [
                { name: 'directory', description: 'Directory path to analyze' },
                { name: 'extension', description: 'File extension to count lines for' }
            ]
        },
        'api-test': {
            name: 'API Endpoint Tester',
            description: 'Test API endpoints and analyze responses',
            commands: [
                'curl -s -w "HTTP Status: %{http_code}\\n" "{api_url}"',
                'curl -s -H "Content-Type: application/json" "{api_url}" | python3 -m json.tool 2>/dev/null || echo "Not valid JSON"',
                'curl -s -I "{api_url}" | grep -E "(Content-Type|Content-Length|Server):"'
            ],
            variables: [
                { name: 'api_url', description: 'API endpoint URL to test' }
            ]
        }
    };
    
    const template = templates[templateType];
    if (template) {
        openToolBuilder();
        document.getElementById('toolName').value = template.name;
        document.getElementById('toolDescription').value = template.description;
        
        // Clear existing commands
        document.getElementById('commandsContainer').innerHTML = '';
        commandCounter = 0;
        
        // Add template commands
        template.commands.forEach(cmd => {
            commandCounter++;
            const container = document.getElementById('commandsContainer');
            const commandDiv = document.createElement('div');
            commandDiv.className = 'command-step';
            commandDiv.innerHTML = `
                <div class="step-number">${commandCounter}</div>
                <input type="text" class="form-input" value="${cmd}" style="margin-top: 1rem;">
                <button type="button" onclick="removeCommand(this)" class="btn-danger" style="margin-top: 0.5rem; float: right;">Remove</button>
            `;
            container.appendChild(commandDiv);
        });
        
        // Clear and add template variables
        document.getElementById('variablesContainer').innerHTML = '';
        template.variables.forEach(variable => {
            const container = document.getElementById('variablesContainer');
            const variableDiv = document.createElement('div');
            variableDiv.style.cssText = 'display: flex; gap: 1rem; margin-bottom: 0.5rem;';
            variableDiv.innerHTML = `
                <input type="text" class="form-input" value="${variable.name}" style="flex: 1;">
                <input type="text" class="form-input" value="${variable.description}" style="flex: 2;">
                <button type="button" onclick="removeVariable(this)" class="btn-danger">Remove</button>
            `;
            container.appendChild(variableDiv);
        });
    }
}

// Form submission
document.getElementById('toolForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const name = document.getElementById('toolName').value;
    const description = document.getElementById('toolDescription').value;
    
    const commands = Array.from(document.querySelectorAll('#commandsContainer input')).map(input => input.value).filter(cmd => cmd.trim());
    
    const variableInputs = document.querySelectorAll('#variablesContainer > div');
    const variables = [];
    variableInputs.forEach(div => {
        const inputs = div.querySelectorAll('input');
        if (inputs[0].value.trim() && inputs[1].value.trim()) {
            variables.push({
                name: inputs[0].value.trim(),
                description: inputs[1].value.trim()
            });
        }
    });
    
    const toolData = {
        name,
        description,
        commands,
        variables
    };
    
    fetch('/api/agent-tools', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(toolData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            closeToolBuilder();
            loadTools();
            showToast('Tool created successfully!', 'success');
        } else {
            showToast(data.error || 'Failed to create tool', 'error');
        }
    })
    .catch(error => {
        console.error('Error creating tool:', error);
        showToast('Error creating tool', 'error');
    });
});

function runTool(toolId) {
    const tool = tools.find(t => t.id === toolId);
    if (!tool) return;
    
    // Show variable input modal if tool has variables
    if (tool.variables && tool.variables.length > 0) {
        showVariableInputModal(tool);
    } else {
        executeToolWithVariables(toolId, {});
    }
}

function showVariableInputModal(tool) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.display = 'block';
    modal.innerHTML = `
        <div class="modal-content">
            <h2>Enter Variables for ${tool.name}</h2>
            <form id="variableForm">
                ${tool.variables.map(variable => `
                    <div class="form-group">
                        <label class="form-label">${variable.name}</label>
                        <input type="text" name="${variable.name}" class="form-input" placeholder="${variable.description}" required>
                    </div>
                `).join('')}
                <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 2rem;">
                    <button type="button" onclick="this.closest('.modal').remove()" class="btn-secondary">Cancel</button>
                    <button type="submit" class="btn-primary">Run Tool</button>
                </div>
            </form>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    modal.querySelector('#variableForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const variables = Object.fromEntries(formData.entries());
        modal.remove();
        executeToolWithVariables(tool.id, variables);
    });
}

function executeToolWithVariables(toolId, variables) {
    fetch(`/api/agent-tools/${toolId}/execute`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ variables })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Tool execution started!', 'success');
            loadTools(); // Refresh to show updated status
            pollToolStatus(toolId);
        } else {
            showToast(data.error || 'Failed to execute tool', 'error');
        }
    })
    .catch(error => {
        console.error('Error executing tool:', error);
        showToast('Error executing tool', 'error');
    });
}

function pollToolStatus(toolId) {
    const interval = setInterval(() => {
        fetch(`/api/agent-tools/${toolId}/status`)
            .then(response => response.json())
            .then(data => {
                if (data.status !== 'running') {
                    clearInterval(interval);
                    loadTools(); // Refresh tools display
                    if (data.status === 'completed') {
                        showToast('Tool execution completed!', 'success');
                    } else if (data.status === 'error') {
                        showToast('Tool execution failed', 'error');
                    }
                }
            })
            .catch(error => {
                console.error('Error polling status:', error);
                clearInterval(interval);
            });
    }, 2000);
}

function deleteTool(toolId) {
    if (confirm('Are you sure you want to delete this tool?')) {
        fetch(`/api/agent-tools/${toolId}`, {
            method: 'DELETE'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadTools();
                showToast('Tool deleted successfully!', 'success');
            } else {
                showToast(data.error || 'Failed to delete tool', 'error');
            }
        })
        .catch(error => {
            console.error('Error deleting tool:', error);
            showToast('Error deleting tool', 'error');
        });
    }
}

function showToast(message, type) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        color: white;
        font-weight: 600;
        z-index: 10000;
        animation: slideIn 0.3s ease;
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}
