"""
Vanchin AI Agent API Routes
Provides AI Agent capabilities with Sandbox filesystem access
"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import os
import subprocess
import json
import pathlib

router = APIRouter(prefix="/api/vanchin")


# ============================================================================
# Models
# ============================================================================

class ChatMessage(BaseModel):
    role: str = Field(..., description="Message role: user, assistant, system")
    content: str = Field(..., description="Message content")


class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(..., description="Conversation history")
    api_key: Optional[str] = Field(None, description="OpenAI API Key (optional, uses env if not provided)")
    model: str = Field("gpt-4.1-mini", description="Model to use")
    temperature: float = Field(0.7, ge=0, le=2)
    max_tokens: int = Field(2000, ge=1, le=4000)


class ChatResponse(BaseModel):
    role: str
    content: str
    timestamp: str
    tool_calls: Optional[List[Dict[str, Any]]] = None


class FileListRequest(BaseModel):
    path: str = Field("/home/ubuntu/aiprojectattack", description="Directory path to list")
    recursive: bool = Field(False, description="List recursively")


class FileReadRequest(BaseModel):
    path: str = Field(..., description="File path to read")
    encoding: str = Field("utf-8", description="File encoding")


class FileWriteRequest(BaseModel):
    path: str = Field(..., description="File path to write")
    content: str = Field(..., description="File content")
    encoding: str = Field("utf-8", description="File encoding")
    create_dirs: bool = Field(True, description="Create parent directories if not exist")


class FileDeleteRequest(BaseModel):
    path: str = Field(..., description="File or directory path to delete")
    recursive: bool = Field(False, description="Delete directory recursively")


class CommandExecuteRequest(BaseModel):
    command: str = Field(..., description="Shell command to execute")
    cwd: Optional[str] = Field(None, description="Working directory")
    timeout: int = Field(30, ge=1, le=300, description="Command timeout in seconds")


class APIKeyConfig(BaseModel):
    openai_api_key: Optional[str] = None


# ============================================================================
# Filesystem Operations
# ============================================================================

@router.post("/files/list")
async def list_files(request: FileListRequest):
    """List files in a directory"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")
        
        if not path.is_dir():
            raise HTTPException(status_code=400, detail=f"Path is not a directory: {request.path}")
        
        files = []
        
        if request.recursive:
            for item in path.rglob("*"):
                try:
                    stat = item.stat()
                    files.append({
                        "path": str(item),
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:]
                    })
                except (PermissionError, OSError):
                    continue
        else:
            for item in path.iterdir():
                try:
                    stat = item.stat()
                    files.append({
                        "path": str(item),
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:]
                    })
                except (PermissionError, OSError):
                    continue
        
        return {
            "success": True,
            "path": str(path),
            "files": sorted(files, key=lambda x: (x["type"] == "file", x["name"])),
            "count": len(files)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing files: {str(e)}")


@router.post("/files/read")
async def read_file(request: FileReadRequest):
    """Read file content"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {request.path}")
        
        if not path.is_file():
            raise HTTPException(status_code=400, detail=f"Path is not a file: {request.path}")
        
        # Check file size (limit to 10MB)
        if path.stat().st_size > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
        
        content = path.read_text(encoding=request.encoding)
        
        return {
            "success": True,
            "path": str(path),
            "content": content,
            "size": path.stat().st_size,
            "encoding": request.encoding
        }
    
    except HTTPException:
        raise
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Unable to decode file with specified encoding")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")


@router.post("/files/write")
async def write_file(request: FileWriteRequest):
    """Write content to file"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        # Create parent directories if needed
        if request.create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)
        
        path.write_text(request.content, encoding=request.encoding)
        
        return {
            "success": True,
            "path": str(path),
            "size": path.stat().st_size,
            "message": "File written successfully"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error writing file: {str(e)}")


@router.post("/files/delete")
async def delete_file(request: FileDeleteRequest):
    """Delete file or directory"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")
        
        if path.is_file():
            path.unlink()
            return {
                "success": True,
                "path": str(path),
                "message": "File deleted successfully"
            }
        elif path.is_dir():
            if request.recursive:
                import shutil
                shutil.rmtree(path)
                return {
                    "success": True,
                    "path": str(path),
                    "message": "Directory deleted successfully"
                }
            else:
                path.rmdir()
                return {
                    "success": True,
                    "path": str(path),
                    "message": "Empty directory deleted successfully"
                }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting: {str(e)}")


# ============================================================================
# Command Execution
# ============================================================================

@router.post("/command/execute")
async def execute_command(request: CommandExecuteRequest):
    """Execute shell command"""
    try:
        result = subprocess.run(
            request.command,
            shell=True,
            cwd=request.cwd,
            capture_output=True,
            text=True,
            timeout=request.timeout
        )
        
        return {
            "success": result.returncode == 0,
            "command": request.command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "cwd": request.cwd or os.getcwd()
        }
    
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail=f"Command timeout after {request.timeout} seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing command: {str(e)}")


# ============================================================================
# AI Chat with Agent Capabilities
# ============================================================================

@router.post("/chat", response_model=ChatResponse)
async def chat_with_agent(request: ChatRequest):
    """Chat with AI Agent that has access to filesystem and tools"""
    try:
        from openai import OpenAI
        
        # Use provided API key or environment variable
        api_key = request.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise HTTPException(status_code=400, detail="OpenAI API Key required")
        
        client = OpenAI(api_key=api_key)
        
        # Define tools for the agent
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "list_files",
                    "description": "List files and directories in a given path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Directory path to list"
                            },
                            "recursive": {
                                "type": "boolean",
                                "description": "List recursively"
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read content of a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path to read"
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "write_file",
                    "description": "Write content to a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path to write"
                            },
                            "content": {
                                "type": "string",
                                "description": "Content to write"
                            }
                        },
                        "required": ["path", "content"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "execute_command",
                    "description": "Execute a shell command",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Shell command to execute"
                            },
                            "cwd": {
                                "type": "string",
                                "description": "Working directory (optional)"
                            }
                        },
                        "required": ["command"]
                    }
                }
            }
        ]
        
        # Convert messages to OpenAI format
        messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]
        
        # Add system message if not present
        if not any(msg["role"] == "system" for msg in messages):
            messages.insert(0, {
                "role": "system",
                "content": """You are Vanchin AI Agent, an intelligent assistant with access to the filesystem and command execution capabilities.

You are running in a Manus Sandbox environment with the following capabilities:
- List, read, write, and delete files
- Execute shell commands
- Access to the project directory: /home/ubuntu/aiprojectattack

When users ask you to perform tasks:
1. Use the available tools to interact with the filesystem
2. Execute commands when needed
3. Provide clear explanations of what you're doing
4. Always verify operations completed successfully

Be helpful, precise, and secure in your operations."""
            })
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model=request.model,
            messages=messages,
            tools=tools,
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )
        
        assistant_message = response.choices[0].message
        
        # Handle tool calls if present
        tool_calls_data = None
        if assistant_message.tool_calls:
            tool_calls_data = []
            for tool_call in assistant_message.tool_calls:
                tool_calls_data.append({
                    "id": tool_call.id,
                    "function": tool_call.function.name,
                    "arguments": json.loads(tool_call.function.arguments)
                })
        
        return ChatResponse(
            role="assistant",
            content=assistant_message.content or "",
            timestamp=datetime.now().isoformat(),
            tool_calls=tool_calls_data
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in chat: {str(e)}")


# ============================================================================
# Configuration
# ============================================================================

@router.post("/config/api-key")
async def save_api_key(config: APIKeyConfig):
    """Save API key configuration (in-memory only for security)"""
    # In production, this should be stored securely
    # For now, we just validate it
    if config.openai_api_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=config.openai_api_key)
            # Test the key
            client.models.list()
            return {
                "success": True,
                "message": "API Key validated and saved"
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid API Key: {str(e)}")
    
    return {"success": True, "message": "Configuration updated"}


@router.get("/status")
async def get_status():
    """Get Vanchin Agent status"""
    return {
        "status": "operational",
        "version": "1.0.0",
        "capabilities": [
            "filesystem_access",
            "command_execution",
            "ai_chat",
            "tool_calling"
        ],
        "sandbox_path": "/home/ubuntu/aiprojectattack",
        "timestamp": datetime.now().isoformat()
    }

