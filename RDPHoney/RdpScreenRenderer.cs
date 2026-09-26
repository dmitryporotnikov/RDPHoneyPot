using System;
using System.IO;
using StbImageSharp;
using StbImageWriteSharp;

namespace RDPHoney
{
    // Purpose: Generates and streams graphical desktop and login screens to RDP clients via Fast-Path Bitmap Updates.
    //
    // Dmitry Porotnikov

    public static class RdpScreenRenderer
    {
        public static string GetStaticJpgPath()
        {
            var env = Environment.GetEnvironmentVariable("STATIC_JPG_PATH")
                      ?? Environment.GetEnvironmentVariable("STATIC_IMAGE_PATH");

            if (!string.IsNullOrWhiteSpace(env))
            {
                return env.Trim();
            }

            return Path.Combine("assets", "desktop.jpg");
        }

        public static void EnsureDefaultStaticJpgExists()
        {
            string path = GetStaticJpgPath();
            if (File.Exists(path))
            {
                return;
            }

            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            int width = 1024;
            int height = 768;
            byte[] rgb = GenerateDefaultDesktopBitmap(width, height);

            var writer = new ImageWriter();
            using var fs = File.OpenWrite(path);
            writer.WriteJpg(rgb, width, height, StbImageWriteSharp.ColorComponents.RedGreenBlue, fs, 90);
        }

        public static byte[] LoadStaticJpgRgb(int targetWidth, int targetHeight)
        {
            EnsureDefaultStaticJpgExists();
            string path = GetStaticJpgPath();

            if (File.Exists(path))
            {
                try
                {
                    byte[] fileBytes = File.ReadAllBytes(path);
                    var image = ImageResult.FromMemory(fileBytes, StbImageSharp.ColorComponents.RedGreenBlue);

                    if (image.Width == targetWidth && image.Height == targetHeight)
                    {
                        return image.Data;
                    }

                    // Rescale / crop to target dimensions
                    return RescaleRgb(image.Data, image.Width, image.Height, targetWidth, targetHeight);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading static JPG ({path}): {ex.Message}. Falling back to generated desktop.");
                }
            }

            return GenerateDefaultDesktopBitmap(targetWidth, targetHeight);
        }

        public static byte[] GenerateDefaultDesktopBitmap(int width, int height)
        {
            byte[] buffer = new byte[width * height * 3];

            // Background gradient: dark navy/slate blue
            for (int y = 0; y < height; y++)
            {
                float t = (float)y / height;
                byte r = (byte)(15 + t * 25);
                byte g = (byte)(30 + t * 50);
                byte b = (byte)(60 + t * 90);

                int rowOffset = y * width * 3;
                for (int x = 0; x < width; x++)
                {
                    int offset = rowOffset + x * 3;
                    buffer[offset] = r;
                    buffer[offset + 1] = g;
                    buffer[offset + 2] = b;
                }
            }

            // Taskbar at the bottom (40px high)
            int taskbarHeight = 40;
            int taskbarTop = Math.Max(0, height - taskbarHeight);
            FillRect(buffer, width, height, 0, taskbarTop, width, taskbarHeight, 20, 24, 30);
            DrawHLine(buffer, width, height, 0, width, taskbarTop, 50, 55, 65);

            // Start button icon
            FillRect(buffer, width, height, 12, taskbarTop + 8, 24, 24, 0, 120, 215);
            FillRect(buffer, width, height, 23, taskbarTop + 8, 2, 24, 20, 24, 30);
            FillRect(buffer, width, height, 12, taskbarTop + 19, 24, 2, 20, 24, 30);

            // Search box
            FillRect(buffer, width, height, 48, taskbarTop + 6, 180, 28, 40, 45, 55);
            DrawString(buffer, width, height, 60, taskbarTop + 14, "Type here to search", 160, 165, 175);

            // System Tray / Clock
            string clock = DateTime.Now.ToString("h:mm tt");
            string date = DateTime.Now.ToString("M/d/yyyy");
            DrawString(buffer, width, height, width - 90, taskbarTop + 8, clock, 220, 225, 230);
            DrawString(buffer, width, height, width - 90, taskbarTop + 22, date, 170, 175, 180);

            // Desktop Icons
            DrawDesktopIcon(buffer, width, height, 20, 20, "This PC", 0, 150, 255);
            DrawDesktopIcon(buffer, width, height, 20, 100, "Server Mgr", 230, 120, 30);
            DrawDesktopIcon(buffer, width, height, 20, 180, "PowerShell", 10, 50, 180);
            DrawDesktopIcon(buffer, width, height, 20, 260, "Recycle Bin", 180, 180, 190);

            // Watermark
            string watermark1 = "Windows Server";
            string watermark2 = "Honeypot Active - Session Monitored";
            DrawString(buffer, width, height, width - 260, height - 90, watermark1, 140, 150, 165, scale: 2);
            DrawString(buffer, width, height, width - 260, height - 65, watermark2, 100, 110, 125, scale: 1);

            return buffer;
        }

        public static byte[] GenerateLoginScreenRgb(int width, int height, string username, string password, bool isPasswordActive)
        {
            byte[] buffer = new byte[width * height * 3];

            // Deep azure/blue lock screen gradient
            for (int y = 0; y < height; y++)
            {
                float t = (float)y / height;
                byte r = (byte)(10 + t * 15);
                byte g = (byte)(25 + t * 40);
                byte b = (byte)(65 + t * 80);

                int rowOffset = y * width * 3;
                for (int x = 0; x < width; x++)
                {
                    int offset = rowOffset + x * 3;
                    buffer[offset] = r;
                    buffer[offset + 1] = g;
                    buffer[offset + 2] = b;
                }
            }

            // Centered login card
            int cardW = 380;
            int cardH = 320;
            int cardX = (width - cardW) / 2;
            int cardY = (height - cardH) / 2;

            // Semi-transparent card back
            FillRect(buffer, width, height, cardX, cardY, cardW, cardH, 20, 32, 50);
            DrawRect(buffer, width, height, cardX, cardY, cardW, cardH, 60, 85, 120);

            // Avatar circle
            int avatarRadius = 32;
            int avatarCenterX = cardX + cardW / 2;
            int avatarCenterY = cardY + 50;
            FillCircle(buffer, width, height, avatarCenterX, avatarCenterY, avatarRadius, 0, 120, 215);
            FillCircle(buffer, width, height, avatarCenterX, avatarCenterY - 10, 12, 255, 255, 255);
            FillCircle(buffer, width, height, avatarCenterX, avatarCenterY + 22, 20, 255, 255, 255);

            // Title
            string title = "Windows Server";
            int titleX = cardX + (cardW - title.Length * 16) / 2;
            DrawString(buffer, width, height, titleX, cardY + 100, title, 255, 255, 255, scale: 2);

            // Username input box
            int inputX = cardX + 30;
            int inputW = cardW - 60;
            int inputH = 34;
            int userY = cardY + 145;

            DrawString(buffer, width, height, inputX, userY - 14, "User name", 180, 200, 220);
            FillRect(buffer, width, height, inputX, userY, inputW, inputH, 255, 255, 255);
            DrawRect(buffer, width, height, inputX, userY, inputW, inputH, !isPasswordActive ? (byte)0 : (byte)150, !isPasswordActive ? (byte)120 : (byte)150, !isPasswordActive ? (byte)215 : (byte)150);

            string userDisplay = string.IsNullOrEmpty(username) ? (!isPasswordActive ? "" : "Administrator") : username;
            DrawString(buffer, width, height, inputX + 10, userY + 10, userDisplay, 30, 30, 30);
            if (!isPasswordActive)
            {
                // Draw blinking-style cursor
                int cursorX = inputX + 10 + userDisplay.Length * 8;
                DrawVLine(buffer, width, height, cursorX, userY + 6, userY + 26, 0, 0, 0);
            }

            // Password input box
            int passY = cardY + 215;
            DrawString(buffer, width, height, inputX, passY - 14, "Password", 180, 200, 220);
            FillRect(buffer, width, height, inputX, passY, inputW, inputH, 255, 255, 255);
            DrawRect(buffer, width, height, inputX, passY, inputW, inputH, isPasswordActive ? (byte)0 : (byte)150, isPasswordActive ? (byte)120 : (byte)150, isPasswordActive ? (byte)215 : (byte)150);

            string passMasked = new string('•', password.Length);
            DrawString(buffer, width, height, inputX + 10, passY + 10, passMasked, 30, 30, 30);
            if (isPasswordActive)
            {
                int cursorX = inputX + 10 + passMasked.Length * 8;
                DrawVLine(buffer, width, height, cursorX, passY + 6, passY + 26, 0, 0, 0);
            }

            // Sign In button / instructions
            string hint = "Press TAB to switch fields | ENTER to Sign in";
            int hintX = cardX + (cardW - hint.Length * 8) / 2;
            DrawString(buffer, width, height, hintX, cardY + 275, hint, 140, 160, 180);

            return buffer;
        }

        public static void SendBitmapUpdate(Stream stream, byte[] rgbPixels, int width, int height)
        {
            // Send uncompressed 24bpp BGR strips via RDP Fast-Path Bitmap Updates
            // Each strip covers 'stripHeight' rows to keep individual packet size under 32KB
            int stripHeight = Math.Max(1, 24000 / (width * 3)); // usually 10-16 rows for 800-1920 width

            for (int top = 0; top < height; top += stripHeight)
            {
                int currentStripH = Math.Min(stripHeight, height - top);
                int bottom = top + currentStripH - 1;

                int stripPixelBytes = width * currentStripH * 3;
                byte[] bgrData = new byte[stripPixelBytes];

                // In RDP standard uncompressed bitmap, pixels are bottom-up BGR
                for (int row = 0; row < currentStripH; row++)
                {
                    int srcY = top + row;
                    int destRow = currentStripH - 1 - row; // bottom-up

                    int srcOffset = srcY * width * 3;
                    int destOffset = destRow * width * 3;

                    for (int x = 0; x < width; x++)
                    {
                        byte r = rgbPixels[srcOffset + x * 3];
                        byte g = rgbPixels[srcOffset + x * 3 + 1];
                        byte b = rgbPixels[srcOffset + x * 3 + 2];

                        bgrData[destOffset + x * 3] = b;     // Blue
                        bgrData[destOffset + x * 3 + 1] = g; // Green
                        bgrData[destOffset + x * 3 + 2] = r; // Red
                    }
                }

                // Construct TS_UPDATE_BITMAP_DATA
                // numberRectangles (2 bytes) = 1
                // destLeft (2) = 0, destTop (2) = top, destRight (2) = width - 1, destBottom (2) = bottom
                // width (2) = width, height (2) = currentStripH
                // bitsPerPixel (2) = 24
                // flags (2) = 0x0000
                // bitmapLength (2) = stripPixelBytes
                // bitmapData = bgrData

                // Payload:
                // updateType (2 bytes, LE: 0x0001 = UPDATE_TYPE_BITMAP)
                // numberRectangles (2 bytes, LE: 0x0001)
                // Rectangle Header (18 bytes)
                // Bitmap Data (stripPixelBytes)
                int updateDataLength = 2 + 2 + 18 + stripPixelBytes;

                // Total Fast-Path PDU length:
                // fpOutputHeader (1 byte: 0x00)
                // length1 & length2 (2 bytes: 0x8000 | totalLength)
                // updateHeader (1 byte: 0x01 = FASTPATH_UPDATETYPE_BITMAP)
                // updateDataLength
                int totalLength = 1 + 2 + 1 + updateDataLength;

                using var ms = new MemoryStream(totalLength);

                // Fast-Path Output Header (3 bytes)
                ms.WriteByte(RdpProtocolConstants.FASTPATH_OUTPUT_ACTION_FASTPATH);
                ms.WriteByte((byte)(0x80 | ((totalLength >> 8) & 0xFF)));
                ms.WriteByte((byte)(totalLength & 0xFF));

                // Update Header: FASTPATH_UPDATETYPE_BITMAP (0x01)
                ms.WriteByte(RdpProtocolConstants.FASTPATH_UPDATETYPE_BITMAP);

                // TS_UPDATE_BITMAP_DATA
                WriteUInt16LE(ms, 1); // updateType = UPDATE_TYPE_BITMAP (1)
                WriteUInt16LE(ms, 1); // numberRectangles = 1

                // Rectangle Header (18 bytes)
                WriteUInt16LE(ms, 0); // destLeft
                WriteUInt16LE(ms, (ushort)top); // destTop
                WriteUInt16LE(ms, (ushort)(width - 1)); // destRight
                WriteUInt16LE(ms, (ushort)bottom); // destBottom
                WriteUInt16LE(ms, (ushort)width); // width
                WriteUInt16LE(ms, (ushort)currentStripH); // height
                WriteUInt16LE(ms, 24); // bitsPerPixel
                WriteUInt16LE(ms, 0); // flags (uncompressed bottom-up)
                WriteUInt16LE(ms, (ushort)stripPixelBytes); // bitmapLength
                ms.Write(bgrData, 0, bgrData.Length);

                byte[] packet = ms.ToArray();
                stream.Write(packet, 0, packet.Length);
            }

            stream.Flush();
        }

        private static void WriteUInt16LE(Stream stream, ushort value)
        {
            stream.WriteByte((byte)(value & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
        }

        private static byte[] RescaleRgb(byte[] src, int srcW, int srcH, int dstW, int dstH)
        {
            byte[] dst = new byte[dstW * dstH * 3];
            float scaleX = (float)srcW / dstW;
            float scaleY = (float)srcH / dstH;

            for (int y = 0; y < dstH; y++)
            {
                int srcY = Math.Clamp((int)(y * scaleY), 0, srcH - 1);
                int dstRow = y * dstW * 3;
                int srcRow = srcY * srcW * 3;

                for (int x = 0; x < dstW; x++)
                {
                    int srcX = Math.Clamp((int)(x * scaleX), 0, srcW - 1);
                    dst[dstRow + x * 3] = src[srcRow + srcX * 3];
                    dst[dstRow + x * 3 + 1] = src[srcRow + srcX * 3 + 1];
                    dst[dstRow + x * 3 + 2] = src[srcRow + srcX * 3 + 2];
                }
            }

            return dst;
        }

        // --- Primitive Graphics Helpers ---

        private static void DrawDesktopIcon(byte[] buffer, int width, int height, int x, int y, string label, byte r, byte g, byte b)
        {
            FillRect(buffer, width, height, x + 4, y, 40, 40, r, g, b);
            DrawRect(buffer, width, height, x + 4, y, 40, 40, 255, 255, 255);
            FillRect(buffer, width, height, x + 10, y + 8, 28, 24, 255, 255, 255);
            DrawString(buffer, width, height, x - 2, y + 46, label, 255, 255, 255);
        }

        public static void FillRect(byte[] buffer, int w, int h, int rx, int ry, int rw, int rh, byte r, byte g, byte b)
        {
            int startX = Math.Max(0, rx);
            int endX = Math.Min(w, rx + rw);
            int startY = Math.Max(0, ry);
            int endY = Math.Min(h, ry + rh);

            for (int y = startY; y < endY; y++)
            {
                int row = y * w * 3;
                for (int x = startX; x < endX; x++)
                {
                    int off = row + x * 3;
                    buffer[off] = r;
                    buffer[off + 1] = g;
                    buffer[off + 2] = b;
                }
            }
        }

        public static void DrawRect(byte[] buffer, int w, int h, int rx, int ry, int rw, int rh, byte r, byte g, byte b)
        {
            DrawHLine(buffer, w, h, rx, rx + rw, ry, r, g, b);
            DrawHLine(buffer, w, h, rx, rx + rw, ry + rh - 1, r, g, b);
            DrawVLine(buffer, w, h, rx, ry, ry + rh, r, g, b);
            DrawVLine(buffer, w, h, rx + rw - 1, ry, ry + rh, r, g, b);
        }

        public static void DrawHLine(byte[] buffer, int w, int h, int x1, int x2, int y, byte r, byte g, byte b)
        {
            if (y < 0 || y >= h) return;
            int startX = Math.Max(0, Math.Min(x1, x2));
            int endX = Math.Min(w, Math.Max(x1, x2));
            int row = y * w * 3;
            for (int x = startX; x < endX; x++)
            {
                int off = row + x * 3;
                buffer[off] = r;
                buffer[off + 1] = g;
                buffer[off + 2] = b;
            }
        }

        public static void DrawVLine(byte[] buffer, int w, int h, int x, int y1, int y2, byte r, byte g, byte b)
        {
            if (x < 0 || x >= w) return;
            int startY = Math.Max(0, Math.Min(y1, y2));
            int endY = Math.Min(h, Math.Max(y1, y2));
            for (int y = startY; y < endY; y++)
            {
                int off = (y * w + x) * 3;
                buffer[off] = r;
                buffer[off + 1] = g;
                buffer[off + 2] = b;
            }
        }

        public static void FillCircle(byte[] buffer, int w, int h, int cx, int cy, int radius, byte r, byte g, byte b)
        {
            int r2 = radius * radius;
            for (int dy = -radius; dy <= radius; dy++)
            {
                int y = cy + dy;
                if (y < 0 || y >= h) continue;
                for (int dx = -radius; dx <= radius; dx++)
                {
                    int x = cx + dx;
                    if (x < 0 || x >= w) continue;
                    if (dx * dx + dy * dy <= r2)
                    {
                        int off = (y * w + x) * 3;
                        buffer[off] = r;
                        buffer[off + 1] = g;
                        buffer[off + 2] = b;
                    }
                }
            }
        }

        public static void DrawString(byte[] buffer, int w, int h, int startX, int startY, string text, byte r, byte g, byte b, int scale = 1)
        {
            if (string.IsNullOrEmpty(text)) return;
            int curX = startX;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                DrawChar(buffer, w, h, curX, startY, c, r, g, b, scale);
                curX += 8 * scale;
            }
        }

        public static void DrawChar(byte[] buffer, int w, int h, int x, int y, char c, byte r, byte g, byte b, int scale = 1)
        {
            byte[] glyph = GetFontGlyph(c);
            for (int row = 0; row < 8; row++)
            {
                byte line = glyph[row];
                for (int col = 0; col < 8; col++)
                {
                    if ((line & (0x80 >> col)) != 0)
                    {
                        if (scale == 1)
                        {
                            int px = x + col;
                            int py = y + row;
                            if (px >= 0 && px < w && py >= 0 && py < h)
                            {
                                int off = (py * w + px) * 3;
                                buffer[off] = r;
                                buffer[off + 1] = g;
                                buffer[off + 2] = b;
                            }
                        }
                        else
                        {
                            FillRect(buffer, w, h, x + col * scale, y + row * scale, scale, scale, r, g, b);
                        }
                    }
                }
            }
        }

        private static byte[] GetFontGlyph(char c)
        {
            // Standard 8x8 font representation for ASCII characters
            return c switch
            {
                ' ' => new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                'A' or 'a' => new byte[] { 0x18, 0x3C, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00 },
                'B' or 'b' => new byte[] { 0x7C, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00, 0x00 },
                'C' or 'c' => new byte[] { 0x3C, 0x66, 0x60, 0x60, 0x66, 0x3C, 0x00, 0x00 },
                'D' or 'd' => new byte[] { 0x78, 0x6C, 0x66, 0x66, 0x6C, 0x78, 0x00, 0x00 },
                'E' or 'e' => new byte[] { 0x7E, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00, 0x00 },
                'F' or 'f' => new byte[] { 0x7E, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00, 0x00 },
                'G' or 'g' => new byte[] { 0x3C, 0x66, 0x60, 0x6E, 0x66, 0x3A, 0x00, 0x00 },
                'H' or 'h' => new byte[] { 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00, 0x00 },
                'I' or 'i' => new byte[] { 0x3C, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00 },
                'J' or 'j' => new byte[] { 0x1E, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00, 0x00 },
                'K' or 'k' => new byte[] { 0x66, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0x00, 0x00 },
                'L' or 'l' => new byte[] { 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00, 0x00 },
                'M' or 'm' => new byte[] { 0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x00, 0x00 },
                'N' or 'n' => new byte[] { 0x66, 0x76, 0x7E, 0x6E, 0x66, 0x66, 0x00, 0x00 },
                'O' or 'o' => new byte[] { 0x3C, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00 },
                'P' or 'p' => new byte[] { 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x00, 0x00 },
                'Q' or 'q' => new byte[] { 0x3C, 0x66, 0x66, 0x66, 0x6E, 0x3C, 0x0E, 0x00 },
                'R' or 'r' => new byte[] { 0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x00, 0x00 },
                'S' or 's' => new byte[] { 0x3C, 0x66, 0x30, 0x18, 0x66, 0x3C, 0x00, 0x00 },
                'T' or 't' => new byte[] { 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00 },
                'U' or 'u' => new byte[] { 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, 0x00 },
                'V' or 'v' => new byte[] { 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00, 0x00 },
                'W' or 'w' => new byte[] { 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00, 0x00 },
                'X' or 'x' => new byte[] { 0x66, 0x66, 0x3C, 0x3C, 0x66, 0x66, 0x00, 0x00 },
                'Y' or 'y' => new byte[] { 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00, 0x00 },
                'Z' or 'z' => new byte[] { 0x7E, 0x06, 0x0C, 0x18, 0x30, 0x7E, 0x00, 0x00 },
                '0' => new byte[] { 0x3C, 0x66, 0x6E, 0x76, 0x66, 0x3C, 0x00, 0x00 },
                '1' => new byte[] { 0x18, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00 },
                '2' => new byte[] { 0x3C, 0x66, 0x0C, 0x18, 0x30, 0x7E, 0x00, 0x00 },
                '3' => new byte[] { 0x7E, 0x0C, 0x18, 0x0C, 0x66, 0x3C, 0x00, 0x00 },
                '4' => new byte[] { 0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x00, 0x00 },
                '5' => new byte[] { 0x7E, 0x60, 0x7C, 0x06, 0x66, 0x3C, 0x00, 0x00 },
                '6' => new byte[] { 0x1C, 0x30, 0x7C, 0x66, 0x66, 0x3C, 0x00, 0x00 },
                '7' => new byte[] { 0x7E, 0x06, 0x0C, 0x18, 0x18, 0x18, 0x00, 0x00 },
                '8' => new byte[] { 0x3C, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00, 0x00 },
                '9' => new byte[] { 0x3C, 0x66, 0x66, 0x3E, 0x06, 0x38, 0x00, 0x00 },
                ':' => new byte[] { 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00 },
                '-' => new byte[] { 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00 },
                '.' => new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00 },
                '/' => new byte[] { 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00 },
                '|' => new byte[] { 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00 },
                '*' or '•' => new byte[] { 0x00, 0x18, 0x3C, 0x7E, 0x3C, 0x18, 0x00, 0x00 },
                '[' => new byte[] { 0x3C, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00, 0x00 },
                ']' => new byte[] { 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00, 0x00 },
                _ => new byte[] { 0x00, 0x3C, 0x42, 0x42, 0x42, 0x3C, 0x00, 0x00 } // Box for other
            };
        }
    }
}
