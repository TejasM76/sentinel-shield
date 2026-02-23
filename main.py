import os
import re
import sys
from groq import Groq
from tavily import TavilyClient
from dotenv import load_dotenv
import requests
import chromadb
from bs4 import BeautifulSoup

from security_layer import (
    scan_prompt,
    scan_tool_input,
    sanitize_external_content,
    validate_memory_write,
    scan_output,
    SecurityViolation
)

# Load environment variables from a .env file
load_dotenv()

# ---
# Tier 2: Long-Term Episodic Memory (Vector DB)
# ---
class EpisodicMemory:
    def __init__(self, memory_dir="./chroma_db"):
        self.chroma_client = chromadb.PersistentClient(path=memory_dir)
        self.collection = self.chroma_client.get_or_create_collection(name="episodic_memory")

    def load_memory(self, query: str = "recent context"):
        """Loads semantic summaries of past sessions."""
        try:
            if self.collection.count() == 0:
                return ""
            results = self.collection.query(
                query_texts=[query],
                n_results=min(2, self.collection.count())
            )
            if not results['documents'] or not results['documents'][0]:
                return ""
            return "\n".join(results['documents'][0])
        except Exception as e:
            print(f"[Error] Failed to load episodic memory: {e}")
            return ""

    def save_memory(self, session_summary: str):
        """Saves an end-of-session summary."""
        if not validate_memory_write(session_summary):
            print("[SECURITY] Memory write rejected by Sentinel Shield!")
            return
        print("\n[System] Archiving session to Episodic Vector DB...")
        try:
            doc_id = f"ep_{self.collection.count() + 1}"
            self.collection.add(
                documents=[session_summary],
                ids=[doc_id]
            )
            print(f"[System] Session archived successfully (ID: {doc_id}).")
        except Exception as e:
            print(f"[Error] Failed to save episodic memory: {e}")

# ---
# Tier 3: Enterprise RAG Knowledge Base (Vector DB)
# ---
class KnowledgeBase:
    def __init__(self, kb_dir="./chroma_db"):
        self.chroma_client = chromadb.PersistentClient(path=kb_dir)
        self.collection = self.chroma_client.get_or_create_collection(name="knowledge_base")
        self._initialize_kb()
        
    def _initialize_kb(self):
        """Mock loading of corporate policy documents into RAG database."""
        if self.collection.count() == 0:
            print("[System] Initializing Corporate Knowledge Base...")
            try:
                kb_path = os.path.join(os.path.dirname(__file__), "corporate_policy.txt")
                if os.path.exists(kb_path):
                    with open(kb_path, "r", encoding="utf-8") as f:
                        text = f.read()
                    # A simplistic chunking strategy for the mock demo
                    chunks = text.split("## ")
                    for i, chunk in enumerate(chunks):
                        if chunk.strip():
                            self.collection.add(
                                documents=["## " + chunk],
                                ids=[f"policy_{i}"]
                            )
                    print(f"[System] Corporate KB initialized with {len(chunks)} documents.")
            except Exception as e:
                print(f"[Error] Failed to build KB: {e}")

    def search(self, query: str) -> str:
        """Searches the corporate knowledge base for internal policies."""
        print(f"[Tool] Searching Internal Knowledge Base for: '{query}'")
        try:
            if self.collection.count() == 0:
                return "Error: Internal Knowledge Base is empty."
            results = self.collection.query(
                query_texts=[query],
                n_results=2
            )
            if not results['documents'] or not results['documents'][0]:
                return "No internal policies found for this query."
            return "\n\n".join(results['documents'][0])
        except Exception as e:
            return f"Error: {e}"

# ---
# Environment and Status Checks
# ---
def check_environment():
    if "GROQ_API_KEY" not in os.environ or not os.environ["GROQ_API_KEY"]:
        print("[Error] GROQ_API_KEY not found in .env file! Ensure it is set.")
        return False
    if "TAVILY_API_KEY" not in os.environ or not os.environ["TAVILY_API_KEY"]:
        print("[Error] TAVILY_API_KEY not found in .env file!")
        return False
    return True

# ---
# The Agent's Toolbelt
# ---
def get_tavily_client():
    api_key = os.environ.get("TAVILY_API_KEY")
    if not api_key:
        return None
    return TavilyClient(api_key=api_key)

def web_search(query: str) -> str:
    print(f"[Tool] Searching the web for: '{query}'")
    try:
        tavily_client = get_tavily_client()
        if not tavily_client:
            return "Error: TAVILY_API_KEY is not set. Cannot perform search."
        results = tavily_client.search(query=query, search_depth="basic", max_results=3)
        raw_content = "\n".join([f"Title: {r['title']}\nURL: {r['url']}\nSnippet: {r['content']}" for r in results.get("results", [])])
        # [Phase 3: RAG Protection] Sanitize Results
        return sanitize_external_content(raw_content)
    except Exception as e: return f"Error: {e}"

def read_web_page(url: str) -> str:
    print(f"[Tool] Reading content from URL: {url}")
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')
        raw_content = "\n".join([p.get_text() for p in soup.find_all('p')])[:4000]
        # [Phase 3: RAG Protection] Sanitize Web Pages
        return sanitize_external_content(raw_content)
    except Exception as e: return f"Error: {e}"

# ---
# The Agent's Brain
# ---
def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None
    return Groq(api_key=api_key)

def call_llm(prompt: str, stream: bool = False):
    try:
        client = get_groq_client()
        if not client:
            if stream: return (chunk for chunk in ["Error: GROQ_API_KEY not set."])
            return "Error: GROQ_API_KEY not set."
            
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama-3.3-70b-versatile",
            temperature=0,
            stream=stream
        )
        
        if stream:
            def stream_generator():
                for chunk in chat_completion:
                    if chunk.choices[0].delta.content is not None:
                        yield chunk.choices[0].delta.content
            return stream_generator()
            
        return chat_completion.choices[0].message.content
    except Exception as e: 
        msg = f"Error calling Groq API: {e}"
        if stream: return (chunk for chunk in [msg])
        return msg

# ---
# The Agent's "Operating System" (Prompt with Memory)
# ---
REACT_PROMPT_TEMPLATE = """
You are an elite, highly capable Enterprise Security Assistant designed by Sentinel Shield.

Here is context summarized from the user's past overarching sessions (Episodic Memory):
<long_term_memory>
{long_term_memory}
</long_term_memory>

Here is the immediate back-and-forth context of the current session (Working Memory):
<short_term_memory>
{short_term_memory}
</short_term_memory>

Your goal is to answer the user's current question effectively using your tools.

You have access to the following tools:
- web_search(query: str): Search the public internet for articles and URLs.
- read_web_page(url: str): Read the full content of a public web page.
- query_knowledge_base(query: str): Search Sentinel Corp's internal private databases (e.g. for corporate policies, passwords, incidents, codebase rules).

Research Strategy:
1. Determine if the user's question is asking for public information or internal company knowledge.
2. If internal, use `query_knowledge_base`.
3. If public, use `web_search` and `read_web_page`.
4. Analyze the content to answer the user's question.

To use a tool, you MUST use the following format:
Thought: [Your reasoning and plan.]
Action: [The tool to use, e.g., query_knowledge_base("password requirements")]

If you do NOT need a tool, jump straight to the final answer:
Thought: I have the final answer.
Final Answer: [Your comprehensive answer.]

Let's begin!

User's Current Question: {input}
{agent_scratchpad}
"""

# ---
# The Agent's Execution Loop
# ---
# ---
# The Agent's Execution Loop
# ---
def run_agent(user_query: str, tools: dict, episodic_memory=None, chat_history: list = None):
    agent_scratchpad = ""
    
    # Tier 2: Retrieve episodic memory based on query
    long_term_context = ""
    if episodic_memory is not None:
        long_term_context = episodic_memory.load_memory(query=user_query)
        
    # Tier 1: Construct short-term sliding window
    short_term_context = ""
    if chat_history:
        # Take up to the last 5 turns
        short_term_context = "\n".join(chat_history[-5:])
        
    max_loops = 7
    for loop_count in range(max_loops):
        print(f"\n--- Agent Loop {loop_count + 1} ---")
        full_prompt = REACT_PROMPT_TEMPLATE.format(
            long_term_memory=long_term_context,
            short_term_memory=short_term_context,
            input=user_query,
            agent_scratchpad=agent_scratchpad
        )
        llm_response = ""
        # 1. First, we stream the tokens from the LLM
        # If the UI is attached, we can yield these tokens directly.
        for token in call_llm(full_prompt, stream=True):
            llm_response += token
            # Yield raw tokens if it looks like a final answer is forming
            if "Final Answer:" in llm_response:
                pass # Handled below
                
        print(f"[Agent] Thought process:\n{llm_response}")
        
        # Check if we are at the final answer step to stream it directly to UI
        if "Final Answer:" in llm_response:
            raw_answer = llm_response.split("Final Answer:")[-1].strip()
            # [Phase 5: Output Filtering] Guard user-facing output
            
            # Since we have the full string, let's yield it token by token for the UI
            def safe_stream():
                safe_text = scan_output(raw_answer)
                for char in safe_text.split(" "):
                    yield char + " "
            return safe_stream()
            
        # If it's just thinking or taking an action, we yield the thought back to the UI status block
        yield f"[Agent] Thought process:\n{llm_response}"
        
        action_match = re.search(r"Action:\s*(.*)", llm_response)
        if action_match:
            action_string = action_match.group(1).strip()
            # If the LLM produces a non-tool action like "None" or "N/A", just skip
            if action_string.lower() in ["none", "n/a", "none.", "n/a."]:
                yield llm_response
                return
            
            tool_name = action_string.split('(')[0]
            if tool_name in tools:
                try:
                    tool_input_str = action_string.split('(', 1)[1][:-1]
                    tool_input = eval(tool_input_str, {"__builtins__": None}, {})
                    
                    # [Phase 2: Execution Sandboxing] Before running tool
                    if not scan_tool_input(tool_name, tool_input):
                        observation = "[SECURITY] Sentinel Shield blocked tool execution."
                    else:
                        observation = tools[tool_name](tool_input)
                except Exception as e: observation = f"Error: {e}"
            else: observation = f"Error: Unknown tool '{tool_name}'."
            agent_scratchpad += f"{llm_response}\nObservation: {observation}\n"
        else:
            # Fallback Breakout: If the LLM just talks naturally without formatting tags, return it directly.
            # This prevents infinite looping on simple queries like "hi".
            def fallback_stream():
                safe_text = scan_output(llm_response.strip())
                for char in safe_text.split(" "):
                    yield char + " "
            return fallback_stream()
            
    yield "Agent could not finish in the allowed number of steps."

# ---
# The Main Chat Application Loop
# ---
def main():
    if not check_environment():
        sys.exit(1)

    # Initialize Tier 2 and Tier 3 memories
    episodic_memory = EpisodicMemory()
    knowledge_base = KnowledgeBase()
    
    # Update Toolbelt with KB
    agent_tools = {
        "web_search": web_search, 
        "read_web_page": read_web_page,
        "query_knowledge_base": knowledge_base.search
    }
    
    # Tier 1: Sliding window chat history
    conversation_history = []
    
    print("[System] Enterprise RAG Assistant is online. Type 'quit' or 'exit' to end the session.")
    
    while True:
        try:
            user_input = input("👤 You: ")
            
            if user_input.lower() in ["quit", "exit"]:
                if conversation_history:
                    # Form episodic memory snapshot at the exit
                    full_conversation = "\n".join(conversation_history)
                    summary_prompt = f"Summarize the key takeaways and topics discussed in this session for our permanent episodic memory:\n\n{full_conversation}"
                    summary = call_llm(summary_prompt)
                    episodic_memory.save_memory(summary)
                
                print("[System] Session archived. Goodbye!")
                break
                
            # [Phase 1: Input Inspection]
            user_input = scan_prompt(user_input)
            
        except SecurityViolation as e:
            print(f"[SECURITY] {e}")
            continue

        # Run the agent with 3-Tier memory architecture
        response_generator = run_agent(user_input, agent_tools, episodic_memory, conversation_history)
        
        print("[Assistant]: ", end="")
        full_res = ""
        for chunk in response_generator:
            if isinstance(chunk, str) and "[Agent]" in chunk:
                continue
            print(chunk, end="", flush=True)
            full_res += chunk
        print()
        response = full_res

        # Append to Tier 1 Sliding Window
        conversation_history.append(f"You: {user_input}")
        conversation_history.append(f"Assistant: {response}")

if __name__ == "__main__":
    main()
