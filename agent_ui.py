import streamlit as st
import io
import sys
import sqlite3
import pandas as pd
from contextlib import redirect_stdout
from main import run_agent, check_environment, EpisodicMemory, KnowledgeBase, web_search, read_web_page, call_llm
from security_layer import scan_prompt, SecurityViolation, DB_PATH

st.set_page_config(page_title="Sentinel Shield - Protected AI Agent", page_icon="🛡️", layout="centered")

st.title("🛡️ Sentinel Shield AI")
st.markdown("**Production-grade SecOps for your Agentic RAG System.**")

if not check_environment():
    st.error("Environment check failed! Please ensure Ollama is running and `.env` has `TAVILY_API_KEY`.")
    st.stop()

# --- Navigation ---
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Agent Chat", "SecOps Dashboard"])

# Initialize tools and memory
episodic_memory = EpisodicMemory()
knowledge_base = KnowledgeBase()
agent_tools = {
    "web_search": web_search, 
    "read_web_page": read_web_page,
    "query_knowledge_base": knowledge_base.search
}

if "messages" not in st.session_state:
    st.session_state.messages = []

# --- PAGE: Agent Chat ---
if page == "Agent Chat":
    with st.sidebar:
        st.divider()
        st.subheader("Session Management")
        if st.button("Archive Session & Clear Chat", use_container_width=True):
            if st.session_state.messages:
                full_conv = "\n".join([f"{m['role']}: {m['content']}" for m in st.session_state.messages])
                summary_prompt = f"Summarize the key takeaways and topics discussed in this session for our permanent episodic memory:\n\n{full_conv}"
                with st.spinner("Archiving Session to Vector Database..."):
                    summary = call_llm(summary_prompt)
                    episodic_memory.save_memory(summary)
                st.session_state.messages = []
                st.success("Session archived to ChromaDB and cleared.")
                st.rerun()
    # Display chat messages from history on app rerun
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            if message.get("is_threat"):
                st.error(message["content"], icon="🚨")
            else:
                st.markdown(message["content"])

    # React to user input
    if prompt := st.chat_input("Ask a question, or try a jailbreak prompt..."):
        # Display user message in chat message container
        st.chat_message("user").markdown(prompt)
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            
            try:
                # Phase 1: Input Inspection
                st.info("🛡️ Sentinel Shield: Scanning Input Prompt...", icon="🔍")
                safe_prompt = scan_prompt(prompt)
                st.success("🛡️ Sentinel Shield: Prompt Clean!", icon="✅")
                
                # Memory handling is now done internally by the agent loop
                # current_memory = memory_handler.load_memory()
                
                # Construct Tier 1: Short-term Memory (Sliding Window)
                chat_history_strs = [f"{m['role']}: {m['content']}" for m in st.session_state.messages]
                
                # Using st.status to capture agent reasoning
                response_generator = run_agent(safe_prompt, agent_tools, episodic_memory, chat_history_strs)
                final_response = []
                
                with st.status("Agent Reasoning Loop...", expanded=True) as status:
                    f = io.StringIO()
                    with redirect_stdout(f):
                        # We need to exhaust the generator, routing internal thoughts to the console 
                        # and capturing the final tokens for the UI stream
                        def stream_to_ui():
                            for chunk in response_generator:
                                if isinstance(chunk, str) and ("[Agent]" in chunk or "Observation:" in chunk):
                                    print(chunk) # Goes to the status block
                                else:
                                    final_response.append(chunk)
                                    yield chunk
                                    
                        # Actually run the generator and type it out into the message_placeholder
                        message_placeholder.write_stream(stream_to_ui())
                        
                    st.text(f.getvalue())
                    status.update(label="Agent completed reasoning!", state="complete", expanded=False)
                    
                full_answer = "".join(final_response)
                st.session_state.messages.append({"role": "assistant", "content": full_answer})
                
                # Tier 2 Summarization is now handled by the Sidebar Archive button
                pass
                
            except SecurityViolation as e:
                error_msg = f"**[SECURITY INTERVENTION]** {str(e)}"
                st.error(error_msg, icon="🚨")
                st.session_state.messages.append({"role": "assistant", "content": error_msg, "is_threat": True})

# --- PAGE: SecOps Dashboard ---
elif page == "SecOps Dashboard":
    st.header("SecOps Telemetry Dashboard")
    st.markdown("Live analytics of Sentinel Shield interventions.")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        query = "SELECT timestamp, event_type, action, details FROM security_events ORDER BY timestamp DESC"
        df = pd.read_sql(query, conn)
        conn.close()
        
        if df.empty:
            st.info("No security events logged yet.")
        else:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Events", len(df))
            with col2:
                blocked = df[df["action"].str.contains("BLOCKED")].shape[0]
                st.metric("Total Threats Blocked", blocked)
            with col3:
                allowed = df[df["action"] == "ALLOWED"].shape[0]
                st.metric("Clean Prompts", allowed)
                
            st.divider()
            
            st.subheader("Event Actions Distribution")
            action_counts = df["action"].value_counts().reset_index()
            action_counts.columns = ["Action", "Count"]
            st.bar_chart(action_counts.set_index("Action"))
            
            st.subheader("Raw Security Logs")
            st.dataframe(df, use_container_width=True)
            
    except Exception as e:
        st.error(f"Could not load telemetry database: {e}")
