import asyncio
from backend.llm.nvidia import NvidiaProvider
from backend.llm.gemini import GeminiProvider
from backend.llm.schemas import ChatRequest, ChatMessage

async def test_providers():
    print("=== Testing NVIDIA NIM ===")
    req = ChatRequest(
        messages=[ChatMessage(role="user", content="Calculate 15 plus 22. If you have a tool, use it. Otherwise, answer directly. Say 'I am NVIDIA NIM'.")],
        tools=[{
            "type": "function",
            "function": {
                "name": "add_numbers",
                "description": "Adds two numbers",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "integer"},
                        "b": {"type": "integer"}
                    },
                    "required": ["a", "b"]
                }
            }
        }]
    )
    
    try:
        nvidia = NvidiaProvider()
        print(f"Model: {nvidia.model}")
        resp = await nvidia.chat(req)
        print("NVIDIA Response:")
        if resp.tool_calls:
            print(" Tool Calls:", resp.tool_calls)
        else:
            print(f" Content: {resp.content}")
    except Exception as e:
        print(f"NVIDIA Failed: {e}")

    print("\n=== Testing Google Gemini ===")
    req.messages[0].content = "Calculate 15 plus 22. Say 'I am Google Gemini'."
    try:
        gemini = GeminiProvider()
        print(f"Model: {gemini.model}")
        resp = await gemini.chat(req)
        print("Gemini Response:")
        if resp.tool_calls:
            print(" Tool Calls:", resp.tool_calls)
        else:
            print(f" Content: {resp.content}")
    except Exception as e:
        print(f"Gemini Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_providers())
