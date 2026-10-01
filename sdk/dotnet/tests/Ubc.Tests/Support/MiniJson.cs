using System.Text;

namespace Ubc.Tests.Support;

/// <summary>
/// A minimal, dependency-free JSON reader scoped to what spec/vectors/vectors.json actually
/// contains (objects, arrays, strings, non-negative integers, booleans, null). Test/tooling-only
/// code — not shipped in the library — written by hand instead of adding a JSON library
/// dependency, mirroring the same choice the Rust and Java ports' test support already make
/// for this same file.
/// </summary>
public static class MiniJson
{
    public static object? Parse(byte[] input)
    {
        int offset = 0;
        var value = ParseValue(input, ref offset);
        SkipWhitespace(input, ref offset);
        if (offset != input.Length)
        {
            throw new FormatException($"unexpected JSON content at byte {offset}");
        }
        return value;
    }

    public static Dictionary<string, object?> AsObject(object? value) =>
        value as Dictionary<string, object?> ?? throw new FormatException("expected a JSON object");

    public static List<object?> AsArray(object? value) =>
        value as List<object?> ?? throw new FormatException("expected a JSON array");

    public static string AsString(object? value) =>
        value as string ?? throw new FormatException("expected a JSON string");

    public static long AsNumber(object? value) =>
        value is long number ? number : throw new FormatException("expected a JSON number");

    private static object? ParseValue(byte[] input, ref int offset)
    {
        SkipWhitespace(input, ref offset);
        if (offset >= input.Length)
        {
            throw new FormatException($"invalid JSON value at byte {offset}");
        }
        return input[offset] switch
        {
            (byte)'n' => ParseLiteral(input, ref offset, "null", null),
            (byte)'t' => ParseLiteral(input, ref offset, "true", true),
            (byte)'f' => ParseLiteral(input, ref offset, "false", false),
            (byte)'"' => ParseString(input, ref offset),
            (byte)'[' => ParseArray(input, ref offset),
            (byte)'{' => ParseObject(input, ref offset),
            >= (byte)'0' and <= (byte)'9' => ParseNumber(input, ref offset),
            _ => throw new FormatException($"invalid JSON value at byte {offset}"),
        };
    }

    private static object? ParseLiteral(byte[] input, ref int offset, string expected, object? value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(expected);
        if (offset + bytes.Length > input.Length || !input.AsSpan(offset, bytes.Length).SequenceEqual(bytes))
        {
            throw new FormatException($"invalid JSON literal at byte {offset}");
        }
        offset += bytes.Length;
        return value;
    }

    private static long ParseNumber(byte[] input, ref int offset)
    {
        int start = offset;
        while (offset < input.Length && input[offset] is >= (byte)'0' and <= (byte)'9')
        {
            offset++;
        }
        return long.Parse(Encoding.ASCII.GetString(input, start, offset - start));
    }

    private static string ParseString(byte[] input, ref int offset)
    {
        Expect(input, ref offset, (byte)'"');
        var output = new StringBuilder();
        while (true)
        {
            if (offset >= input.Length)
            {
                throw new FormatException("unterminated JSON string");
            }
            byte b = input[offset++];
            if (b == (byte)'"')
            {
                return output.ToString();
            }
            if (b == (byte)'\\')
            {
                ParseEscape(input, ref offset, output);
            }
            else if (b < 0x20)
            {
                throw new FormatException("control byte in JSON string");
            }
            else
            {
                output.Append((char)b);
            }
        }
    }

    private static void ParseEscape(byte[] input, ref int offset, StringBuilder output)
    {
        if (offset >= input.Length)
        {
            throw new FormatException("truncated JSON escape");
        }
        byte b = input[offset++];
        switch (b)
        {
            case (byte)'"': output.Append('"'); break;
            case (byte)'\\': output.Append('\\'); break;
            case (byte)'/': output.Append('/'); break;
            case (byte)'b': output.Append('\b'); break;
            case (byte)'f': output.Append('\f'); break;
            case (byte)'n': output.Append('\n'); break;
            case (byte)'r': output.Append('\r'); break;
            case (byte)'t': output.Append('\t'); break;
            case (byte)'u':
                if (offset + 4 > input.Length)
                {
                    throw new FormatException("truncated JSON unicode escape");
                }
                string digits = Encoding.ASCII.GetString(input, offset, 4);
                output.Append((char)Convert.ToInt32(digits, 16));
                offset += 4;
                break;
            default:
                throw new FormatException("invalid JSON escape");
        }
    }

    private static List<object?> ParseArray(byte[] input, ref int offset)
    {
        Expect(input, ref offset, (byte)'[');
        var values = new List<object?>();
        SkipWhitespace(input, ref offset);
        if (Consume(input, ref offset, (byte)']'))
        {
            return values;
        }
        while (true)
        {
            values.Add(ParseValue(input, ref offset));
            SkipWhitespace(input, ref offset);
            if (Consume(input, ref offset, (byte)']'))
            {
                return values;
            }
            Expect(input, ref offset, (byte)',');
        }
    }

    private static Dictionary<string, object?> ParseObject(byte[] input, ref int offset)
    {
        Expect(input, ref offset, (byte)'{');
        var values = new Dictionary<string, object?>();
        SkipWhitespace(input, ref offset);
        if (Consume(input, ref offset, (byte)'}'))
        {
            return values;
        }
        while (true)
        {
            SkipWhitespace(input, ref offset);
            string key = ParseString(input, ref offset);
            SkipWhitespace(input, ref offset);
            Expect(input, ref offset, (byte)':');
            var value = ParseValue(input, ref offset);
            if (!values.TryAdd(key, value))
            {
                throw new FormatException($"duplicate JSON object key: {key}");
            }
            SkipWhitespace(input, ref offset);
            if (Consume(input, ref offset, (byte)'}'))
            {
                return values;
            }
            Expect(input, ref offset, (byte)',');
        }
    }

    private static void SkipWhitespace(byte[] input, ref int offset)
    {
        while (offset < input.Length && input[offset] is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r')
        {
            offset++;
        }
    }

    private static void Expect(byte[] input, ref int offset, byte expected)
    {
        if (offset >= input.Length || input[offset] != expected)
        {
            throw new FormatException($"expected '{(char)expected}' at byte {offset}");
        }
        offset++;
    }

    private static bool Consume(byte[] input, ref int offset, byte expected)
    {
        if (offset < input.Length && input[offset] == expected)
        {
            offset++;
            return true;
        }
        return false;
    }
}
