import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class BinaryXmlParser {
    private static final int RES_XML_TYPE = 0x0003;
    private static final int CHUNK_STRING_POOL = 0x0001;
    private static final int CHUNK_RESOURCE_MAP = 0x0180;
    private static final int CHUNK_START_NAMESPACE = 0x0100;
    private static final int CHUNK_END_NAMESPACE = 0x0101;
    private static final int CHUNK_START_TAG = 0x0102;
    private static final int CHUNK_END_TAG = 0x0103;
    private static final int TYPE_STRING = 0x03;

    private BinaryXmlParser() {
    }

    public static boolean isBinaryXml(byte[] bytes) {
        if (bytes.length < 8) {
            return false;
        }
        int type = ushort(bytes, 0);
        return type == RES_XML_TYPE;
    }

    public static byte[] decodeToUtf8(byte[] axmlBytes) {
        ByteBuffer buffer = ByteBuffer.wrap(axmlBytes).order(ByteOrder.LITTLE_ENDIAN);
        int xmlType = ushort(buffer, 0);
        if (xmlType != RES_XML_TYPE) {
            throw new IllegalArgumentException("Not an Android binary XML document");
        }

        StringPool pool = null;
        List<Integer> resourceMap = new ArrayList<>();
        List<NamespaceFrame> namespaces = new ArrayList<>();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n".getBytes(StandardCharsets.UTF_8));

        int offset = 8;
        int depth = 0;
        while (offset + 8 <= buffer.capacity()) {
            int chunkType = ushort(buffer, offset);
            int headerSize = ushort(buffer, offset + 2);
            int chunkSize = buffer.getInt(offset + 4);
            if (chunkSize <= 0 || offset + chunkSize > buffer.capacity()) {
                break;
            }

            switch (chunkType) {
                case CHUNK_STRING_POOL -> pool = parseStringPool(buffer, offset);
                case CHUNK_RESOURCE_MAP -> {
                    for (int i = offset + headerSize; i < offset + chunkSize; i += 4) {
                        resourceMap.add(buffer.getInt(i));
                    }
                }
                case CHUNK_START_NAMESPACE -> namespaces.add(parseNamespace(buffer, offset, pool));
                case CHUNK_END_NAMESPACE -> removeNamespace(namespaces, parseNamespace(buffer, offset, pool));
                case CHUNK_START_TAG -> {
                    if (pool == null) {
                        throw new IllegalStateException("String pool not parsed before start tag");
                    }
                    StartTag tag = parseStartTag(buffer, offset, pool, resourceMap);
                    indent(out, depth);
                    out.writeBytes(("<" + tag.name).getBytes(StandardCharsets.UTF_8));

                    for (NamespaceFrame namespace : namespaces) {
                        if (!namespace.declared && namespace.prefix != null && !namespace.prefix.isEmpty()) {
                            String decl = " xmlns:" + namespace.prefix + "=\"" + safe(namespace.uri) + "\"";
                            out.writeBytes(decl.getBytes(StandardCharsets.UTF_8));
                            namespace.declared = true;
                        }
                    }

                    for (Attribute attribute : tag.attributes) {
                        String attributeText = " " + attribute.name + "=\"" + safe(attribute.value) + "\"";
                        out.writeBytes(attributeText.getBytes(StandardCharsets.UTF_8));
                    }
                    out.writeBytes(">\n".getBytes(StandardCharsets.UTF_8));
                    depth++;
                }
                case CHUNK_END_TAG -> {
                    if (pool == null) {
                        throw new IllegalStateException("String pool not parsed before end tag");
                    }
                    depth = Math.max(0, depth - 1);
                    EndTag tag = parseEndTag(buffer, offset, pool);
                    indent(out, depth);
                    out.writeBytes(("</" + tag.name + ">\n").getBytes(StandardCharsets.UTF_8));
                }
                default -> {
                }
            }
            offset += chunkSize;
        }
        return out.toByteArray();
    }

    private static StringPool parseStringPool(ByteBuffer buffer, int offset) {
        int stringCount = buffer.getInt(offset + 8);
        int styleCount = buffer.getInt(offset + 12);
        int flags = buffer.getInt(offset + 16);
        int stringsStart = buffer.getInt(offset + 20);
        int stylesStart = buffer.getInt(offset + 24);
        boolean utf8 = (flags & 0x100) != 0;

        int[] offsets = new int[stringCount];
        int offsetBase = offset + 28;
        for (int i = 0; i < stringCount; i++) {
            offsets[i] = buffer.getInt(offsetBase + i * 4);
        }

        int stringsBase = offset + stringsStart;
        int stylesBase = stylesStart == 0 ? offset + buffer.getInt(offset + 4) : offset + stylesStart;
        return new StringPool(buffer, offsets, stringsBase, stylesBase, utf8);
    }

    private static NamespaceFrame parseNamespace(ByteBuffer buffer, int offset, StringPool pool) {
        int prefixIndex = buffer.getInt(offset + 16);
        int uriIndex = buffer.getInt(offset + 20);
        return new NamespaceFrame(pool.get(prefixIndex), pool.get(uriIndex));
    }

    private static void removeNamespace(List<NamespaceFrame> namespaces, NamespaceFrame namespaceFrame) {
        namespaces.removeIf(ns -> ns.prefix.equals(namespaceFrame.prefix) && ns.uri.equals(namespaceFrame.uri));
    }

    private static StartTag parseStartTag(ByteBuffer buffer, int offset, StringPool pool, List<Integer> resourceMap) {
        StartTag tag = new StartTag();
        int namespaceIndex = buffer.getInt(offset + 16);
        int nameIndex = buffer.getInt(offset + 20);
        tag.namespace = pool.get(namespaceIndex);
        tag.name = pool.get(nameIndex);

        int attributeStart = ushort(buffer, offset + 24);
        int attributeSize = ushort(buffer, offset + 26);
        int attributeCount = ushort(buffer, offset + 28);
        // `attributeStart` is relative to the attribute-extension block,
        // which begins right after the 16-byte XML node header.
        int base = offset + 16 + attributeStart;
        for (int i = 0; i < attributeCount; i++) {
            int attributeOffset = base + i * attributeSize;
            Attribute attribute = parseAttribute(buffer, attributeOffset, pool, resourceMap);
            tag.attributes.add(attribute);
        }
        return tag;
    }

    private static EndTag parseEndTag(ByteBuffer buffer, int offset, StringPool pool) {
        EndTag tag = new EndTag();
        int namespaceIndex = buffer.getInt(offset + 16);
        int nameIndex = buffer.getInt(offset + 20);
        tag.namespace = pool.get(namespaceIndex);
        tag.name = pool.get(nameIndex);
        return tag;
    }

    private static Attribute parseAttribute(ByteBuffer buffer, int offset, StringPool pool, List<Integer> resourceMap) {
        int namespaceIndex = buffer.getInt(offset);
        int nameIndex = buffer.getInt(offset + 4);
        int rawValueIndex = buffer.getInt(offset + 8);
        int typedValueSize = ushort(buffer, offset + 12);
        int dataType = ubyte(buffer, offset + 15);
        int data = buffer.getInt(offset + 16);

        Attribute attribute = new Attribute();
        String namespace = pool.get(namespaceIndex);
        String rawName = pool.get(nameIndex);
        attribute.name = qualifyName(namespace, rawName);

        if (rawValueIndex != -1) {
            attribute.value = pool.get(rawValueIndex);
        } else {
            attribute.value = decodeTypedValue(dataType, data, pool);
        }
        return attribute;
    }

    private static String qualifyName(String namespace, String name) {
        if (namespace == null || namespace.isEmpty()) {
            return name;
        }
        if ("http://schemas.android.com/apk/res/android".equals(namespace)) {
            return "android:" + name;
        }
        return name;
    }

    private static String decodeTypedValue(int dataType, int data, StringPool pool) {
        return switch (dataType) {
            case TYPE_STRING -> pool.get(data);
            case 0x12 -> data != 0 ? "true" : "false";
            case 0x10, 0x11 -> Integer.toString(data);
            case 0x01 -> String.format("@0x%08x", data);
            default -> String.format("0x%08x", data);
        };
    }

    private static String safe(String value) {
        return value
            .replace("&", "&amp;")
            .replace("\"", "&quot;")
            .replace("<", "&lt;")
            .replace(">", "&gt;");
    }

    private static void indent(ByteArrayOutputStream out, int depth) {
        for (int i = 0; i < depth; i++) {
            out.writeBytes("  ".getBytes(StandardCharsets.UTF_8));
        }
    }

    private static int ushort(ByteBuffer buffer, int offset) {
        return Short.toUnsignedInt(buffer.getShort(offset));
    }

    private static int ubyte(ByteBuffer buffer, int offset) {
        return Byte.toUnsignedInt(buffer.get(offset));
    }

    private static int ushort(byte[] bytes, int offset) {
        return ((bytes[offset + 1] & 0xFF) << 8) | (bytes[offset] & 0xFF);
    }

    private static final class StringPool {
        private final ByteBuffer buffer;
        private final int[] offsets;
        private final int stringsBase;
        private final int stylesBase;
        private final boolean utf8;

        private StringPool(ByteBuffer buffer, int[] offsets, int stringsBase, int stylesBase, boolean utf8) {
            this.buffer = buffer;
            this.offsets = offsets;
            this.stringsBase = stringsBase;
            this.stylesBase = stylesBase;
            this.utf8 = utf8;
        }

        private String get(int index) {
            if (index < 0 || index >= offsets.length) {
                return "";
            }
            int absoluteOffset = stringsBase + offsets[index];
            return utf8 ? decodeUtf8(absoluteOffset) : decodeUtf16(absoluteOffset);
        }

        private String decodeUtf8(int offset) {
            int[] skippedChars = skipLength8(offset);
            int[] lengthBytes = readLength8(skippedChars[0]);
            int byteCount = lengthBytes[1];
            int start = lengthBytes[0];
            byte[] data = new byte[byteCount];
            for (int i = 0; i < byteCount; i++) {
                data[i] = buffer.get(start + i);
            }
            return new String(data, StandardCharsets.UTF_8);
        }

        private String decodeUtf16(int offset) {
            int[] length = readLength16(offset);
            int chars = length[1];
            int start = length[0];
            byte[] data = new byte[chars * 2];
            for (int i = 0; i < data.length; i++) {
                data[i] = buffer.get(start + i);
            }
            return new String(data, StandardCharsets.UTF_16LE);
        }

        private int[] skipLength8(int offset) {
            int[] first = readLength8(offset);
            return readLength8(first[0]);
        }

        private int[] readLength8(int offset) {
            int first = Byte.toUnsignedInt(buffer.get(offset));
            if ((first & 0x80) == 0) {
                return new int[]{offset + 1, first};
            }
            int second = Byte.toUnsignedInt(buffer.get(offset + 1));
            int value = ((first & 0x7F) << 8) | second;
            return new int[]{offset + 2, value};
        }

        private int[] readLength16(int offset) {
            int first = Short.toUnsignedInt(buffer.getShort(offset));
            if ((first & 0x8000) == 0) {
                return new int[]{offset + 2, first};
            }
            int second = Short.toUnsignedInt(buffer.getShort(offset + 2));
            int value = ((first & 0x7FFF) << 16) | second;
            return new int[]{offset + 4, value};
        }
    }

    private static final class NamespaceFrame {
        private final String prefix;
        private final String uri;
        private boolean declared;

        private NamespaceFrame(String prefix, String uri) {
            this.prefix = prefix == null ? "" : prefix;
            this.uri = uri == null ? "" : uri;
        }
    }

    private static final class StartTag {
        private String namespace;
        private String name;
        private final List<Attribute> attributes = new ArrayList<>();
    }

    private static final class EndTag {
        private String namespace;
        private String name;
    }

    private static final class Attribute {
        private String name;
        private String value;
    }
}
