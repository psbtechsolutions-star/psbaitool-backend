// ==================== AI CHAT PROXY ====================

app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const { messages, system } = req.body || {};

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        error: 'messages array is required'
      });
    }

    if (!process.env.GEMINI_API_KEY) {
      console.error('GEMINI_API_KEY is missing');
      return res.status(500).json({
        error: 'Gemini API key is not configured'
      });
    }

    // Convert frontend messages to Gemini format
    const contents = messages.map((message) => ({
      role: message.role === 'assistant' ? 'model' : 'user',
      parts: [
        {
          text: String(message.content || '')
        }
      ]
    }));

    // Gemini request body
    const body = {
      contents,
      generationConfig: {
        maxOutputTokens: 1000
      }
    };

    // Add system instruction when supplied
    if (system) {
      body.systemInstruction = {
        parts: [
          {
            text: String(system)
          }
        ]
      };
    }

    const response = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': process.env.GEMINI_API_KEY
        },
        body: JSON.stringify(body)
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error('Gemini API error:', response.status, data);

      return res.status(502).json({
        error: 'Gemini API error',
        details: data?.error?.message || 'Unknown Gemini error'
      });
    }

    // Extract Gemini response text
    const text =
      data?.candidates?.[0]?.content?.parts
        ?.map((part) => part.text || '')
        .join('') || '';

    if (!text) {
      console.error('Gemini returned an empty response:', data);

      return res.status(502).json({
        error: 'Gemini returned an empty response'
      });
    }

    // Return format expected by existing PSBAITool frontend
    res.json({
      content: [
        {
          type: 'text',
          text
        }
      ]
    });

  } catch (err) {
    console.error('chat proxy error:', err);

    res.status(500).json({
      error: 'Something went wrong talking to Gemini'
    });
  }
});

// ==================== SERVER ====================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`PSBAITool backend listening on port ${PORT}`);
});
