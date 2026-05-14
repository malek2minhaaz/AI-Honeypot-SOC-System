from openai import OpenAI

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key="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"
)


def ask_ai(question, logs):

    try:

        prompt = f"""
You are an AI SOC Security Analyst.

Analyze these honeypot logs:

{logs}

Admin Question:
{question}

Provide a professional cybersecurity incident summary in paragraph format.

Include:
- detected threat
- severity level
- attack behavior
- possible risks
- mitigation recommendations

Keep response concise, professional, and around 1-2 short paragraphs only.
"""

        completion = client.chat.completions.create(

            model="meta/llama-3.1-8b-instruct",

            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],

            temperature=0.5,
            top_p=1,
            max_tokens=500,
            stream=False
        )

        return completion.choices[0].message.content

    except Exception as e:

        print("FULL ERROR:")
        print(e)

        return f"AI Error: {str(e)}"