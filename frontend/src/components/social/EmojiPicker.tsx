import React, { useState } from "react";
import {
  Box,
  Typography,
  IconButton,
  Paper,
  Tabs,
  Tab,
  TextField,
  InputAdornment,
  Grid,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import SearchIcon from "@mui/icons-material/Search";

// Comprehensive emoji categories
const EMOJI_DATA: Record<string, string[]> = {
  "😀 Smileys": [
    "😀", "😃", "😄", "😁", "😅", "😂", "🤣", "😊", "😇", "🙂", "😉", "😌", "😍", "🥰", "😘",
    "😋", "😛", "😜", "🤪", "😝", "🤑", "🤗", "🤭", "🤫", "🤔", "🤐", "🤨", "😐", "😑", "😶",
    "😏", "😒", "🙄", "😬", "🤥", "😔", "😪", "🤤", "😴", "😷", "🤒", "🤕", "🤢", "🤮",
    "🤧", "🥵", "🥶", "🥴", "😵", "🤯", "🤠", "🥳", "🥸", "😎", "🤓", "🧐", "😕", "😟",
    "🙁", "☹️", "😮", "😯", "😲", "😳", "🥺", "😦", "😧", "😨", "😰", "😥", "😢", "😭",
    "😱", "😖", "😣", "😞", "😓", "😩", "😫", "🥱", "😤", "😡", "😠", "🤬", "😈", "👿",
  ],
  "👋 Gestures": [
    "👍", "👎", "👊", "✊", "🤛", "🤜", "🤞", "✌️", "🤟", "🤘", "👌", "🤌", "🤏", "👈",
    "👉", "👆", "👇", "☝️", "✋", "🤚", "🖐️", "🖖", "👋", "🤙", "💪", "🦾", "🙏", "🤝",
    "👏", "🙌", "👐", "🤲", "✍️", "🤳", "💅", "🖕", "✊", "👊", "🤛", "🤜",
  ],
  "❤️ Hearts": [
    "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔", "❣️", "💕", "💞", "💓",
    "💗", "💖", "💘", "💝", "💟", "♥️", "❤️‍🔥", "❤️‍🩹", "💌",
  ],
  "🐱 Animals": [
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸",
    "🐵", "🐔", "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🦇", "🐺", "🐗", "🐴", "🦄", "🐝",
    "🐛", "🦋", "🐌", "🐞", "🐜", "🦟", "🦗", "🕷️", "🦂", "🐢", "🐍", "🦎", "🦖", "🦕",
    "🐙", "🦑", "🦐", "🦞", "🦀", "🐡", "🐠", "🐟", "🐬", "🐳", "🐋", "🦈", "🐊",
  ],
  "🍔 Food": [
    "🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🫐", "🍈", "🍒", "🍑", "🥭", "🍍",
    "🥥", "🥝", "🍅", "🍆", "🥑", "🥦", "🥬", "🥒", "🌶️", "🫑", "🌽", "🥕", "🧄", "🧅",
    "🥔", "🍠", "🥐", "🥯", "🍞", "🥖", "🥨", "🧀", "🥚", "🍳", "🥞", "🧇", "🥓", "🥩",
    "🍗", "🍖", "🌭", "🍔", "🍟", "🍕", "🥪", "🥙", "🧆", "🌮", "🌯", "🥗", "🥘", "🍝",
    "🍜", "🍲", "🍛", "🍣", "🍱", "🥟", "🍤", "🍙", "🍚", "🍘", "🍥", "🍧", "🍨", "🍦",
    "🧁", "🍰", "🎂", "🍮", "🍭", "🍬", "🍫", "🍿", "🍩", "🍪", "☕", "🍵", "🧃", "🥤",
    "🍶", "🍺", "🍻", "🥂", "🍷", "🥃", "🍸", "🍹", "🧉", "🍾",
  ],
  "⚽ Activities": [
    "⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🏉", "🥏", "🎱", "🏓", "🏸", "🏒", "🏑",
    "🥍", "🏏", "🥅", "⛳", "🏹", "🎣", "🥊", "🥋", "🎽", "🛹", "🛷", "⛸️", "🥌", "🎿",
    "⛷️", "🏂", "🏋️", "🤼", "🤸", "⛹️", "🤾", "🏌️", "🏇", "🧘", "🏄", "🏊", "🤽", "🚣",
    "🧗", "🚵", "🚴", "🏆", "🥇", "🥈", "🥉", "🏅", "🎖️", "🎗️", "🎫", "🎪", "🎭", "🎨",
    "🎬", "🎤", "🎧", "🎼", "🎹", "🥁", "🎷", "🎺", "🎸", "🎻", "🎲", "♟️", "🎯", "🎳",
    "🎮", "🎰", "🧩",
  ],
  "💻 Tech": [
    "💻", "🖥️", "🖨️", "⌨️", "🖱️", "🖲️", "💽", "💾", "💿", "📀", "📷", "📸", "📹", "🎥",
    "📽️", "🎞️", "📞", "☎️", "📟", "📠", "📺", "📻", "🎙️", "🎚️", "🎛️", "🧭", "⏱️", "⏲️",
    "⏰", "🕰️", "⌛", "⏳", "📡", "🔋", "🔌", "💡", "🔦", "🕯️", "💸", "💵", "💴", "💶",
    "💷", "💰", "💳", "💎", "⚖️", "🔧", "🔨", "⛏️", "🔩", "⚙️", "🔫", "💣", "🔪", "🗡️",
    "⚔️", "🛡️", "🔮", "🔬", "🔭", "💊", "💉", "🧬", "🦠", "🧫", "🧪",
  ],
  "🚀 Objects": [
    "🚗", "🚕", "🚙", "🚌", "🚎", "🏎️", "🚓", "🚑", "🚒", "🚐", "🛻", "🚚", "🚛", "🚜",
    "🛴", "🚲", "🛵", "🏍️", "🛺", "🚁", "✈️", "🛫", "🛬", "🛩️", "🚀", "🛸", "🚂", "🚃",
    "🚄", "🚅", "🚆", "🚇", "🚈", "🚉", "🚊", "🚝", "🚞", "🚋", "🚌", "🚍", "🚎", "🚐",
    "⛵", "🛶", "🚤", "🛥️", "🛳️", "⛴️", "🚢", "⚓", "🪝", "⛽", "🚧", "🚦", "🚥", "🗺️",
    "🗿", "🗽", "🗼", "🏰", "🏯", "🏟️", "🎡", "🎢", "🎠", "⛲", "⛱️", "🏖️", "🏝️", "🏜️",
    "🌋", "⛰️", "🏔️", "🗻", "🏕️", "⛺", "🏠", "🏡", "🏘️", "🏚️", "🏗️", "🏢", "🏬", "🏣",
    "🏤", "🏥", "🏦", "🏨", "🏪", "🏫", "🏩", "💒", "🏛️", "⛪", "🕌", "🕍", "🛕", "🕋",
  ],
  "⚠️ Symbols": [
    "❗", "❓", "❕", "❔", "‼️", "⁉️", "💯", "🔅", "🔆", "⚠️", "🚸", "⛔", "🚫", "🚳",
    "🚭", "🚯", "🚱", "🚷", "📵", "🔞", "☢️", "☣️", "✅", "❌", "❎", "✔️", "☑️", "✖️",
    "➕", "➖", "➗", "➰", "➿", "〽️", "✳️", "✴️", "❇️", "©️", "®️", "™️", "#️⃣", "*️⃣",
    "0️⃣", "1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟", "🔠", "🔡",
    "🔢", "🔣", "🔤", "🔴", "🟠", "🟡", "🟢", "🔵", "🟣", "🟤", "⚫", "⚪", "🟥", "🟧",
    "🟨", "🟩", "🟦", "🟪", "🟫", "⬛", "⬜", "◼️", "◻️", "◾", "◽", "▪️", "▫️",
  ],
  "🏁 Flags": [
    "🏁", "🚩", "🎌", "🏴", "🏳️", "🏳️‍🌈", "🏳️‍⚧️", "🏴‍☠️", "🇺🇸", "🇬🇧", "🇨🇦", "🇦🇺",
    "🇩🇪", "🇫🇷", "🇪🇸", "🇮🇹", "🇯🇵", "🇨🇳", "🇰🇷", "🇮🇳", "🇧🇷", "🇲🇽", "🇷🇺", "🇿🇦",
    "🇳🇱", "🇧🇪", "🇸🇪", "🇳🇴", "🇩🇰", "🇫🇮", "🇵🇱", "🇺🇦", "🇮🇪", "🇨🇭", "🇦🇹", "🇵🇹",
    "🇬🇷", "🇹🇷", "🇮🇱", "🇦🇪", "🇸🇦", "🇪🇬", "🇳🇬", "🇰🇪", "🇹🇭", "🇻🇳", "🇵🇭", "🇸🇬",
    "🇲🇾", "🇮🇩", "🇳🇿", "🇦🇷", "🇨🇴", "🇨🇱", "🇵🇪", "🇻🇪",
  ],
};

// Recently used emojis - stored in component state (could be persisted to localStorage)
const RECENT_KEY = "vragent_recent_emojis";

interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
  onClose: () => void;
}

export const EmojiPicker: React.FC<EmojiPickerProps> = ({ onSelect, onClose }) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState(Object.keys(EMOJI_DATA)[0]);
  const [recentEmojis, setRecentEmojis] = useState<string[]>(() => {
    try {
      const saved = localStorage.getItem(RECENT_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const categories = Object.keys(EMOJI_DATA);

  // Filter emojis based on search
  const getFilteredEmojis = (): string[] => {
    if (!searchQuery.trim()) {
      return EMOJI_DATA[selectedCategory] || [];
    }
    // Search across all categories
    const allEmojis: string[] = [];
    Object.values(EMOJI_DATA).forEach((emojis) => {
      allEmojis.push(...emojis);
    });
    return allEmojis;
  };

  const handleEmojiClick = (emoji: string) => {
    // Add to recent
    const newRecent = [emoji, ...recentEmojis.filter((e) => e !== emoji)].slice(0, 24);
    setRecentEmojis(newRecent);
    try {
      localStorage.setItem(RECENT_KEY, JSON.stringify(newRecent));
    } catch {}
    
    onSelect(emoji);
  };

  const handleCategoryChange = (_: React.SyntheticEvent, newValue: string) => {
    setSelectedCategory(newValue);
    setSearchQuery("");
  };

  const filteredEmojis = getFilteredEmojis();

  return (
    <Paper
      elevation={4}
      sx={{
        width: 340,
        maxHeight: 420,
        display: "flex",
        flexDirection: "column",
        borderRadius: 2,
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          p: 1,
          borderBottom: 1,
          borderColor: "divider",
        }}
      >
        <Typography variant="subtitle1" fontWeight="medium">
          Emojis
        </Typography>
        <IconButton size="small" onClick={onClose}>
          <CloseIcon fontSize="small" />
        </IconButton>
      </Box>

      {/* Search */}
      <Box sx={{ px: 1.5, py: 1 }}>
        <TextField
          fullWidth
          size="small"
          placeholder="Search emojis..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {/* Category Tabs */}
      {!searchQuery.trim() && (
        <Tabs
          value={selectedCategory}
          onChange={handleCategoryChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            minHeight: 40,
            borderBottom: 1,
            borderColor: "divider",
            "& .MuiTab-root": {
              minHeight: 40,
              minWidth: 40,
              p: 0.5,
              fontSize: "1.2rem",
            },
          }}
        >
          {recentEmojis.length > 0 && (
            <Tab value="recent" label="🕐" title="Recent" />
          )}
          {categories.map((cat) => (
            <Tab key={cat} value={cat} label={cat.split(" ")[0]} title={cat.split(" ")[1]} />
          ))}
        </Tabs>
      )}

      {/* Emoji Grid */}
      <Box
        sx={{
          flex: 1,
          overflowY: "auto",
          p: 1,
          minHeight: 200,
        }}
      >
        {/* Recent emojis */}
        {!searchQuery.trim() && selectedCategory === "recent" && recentEmojis.length > 0 && (
          <>
            <Typography variant="caption" color="text.secondary" sx={{ px: 0.5 }}>
              Recently Used
            </Typography>
            <Grid container>
              {recentEmojis.map((emoji, index) => (
                <Grid item key={`recent-${index}`}>
                  <Box
                    onClick={() => handleEmojiClick(emoji)}
                    sx={{
                      cursor: "pointer",
                      p: 0.75,
                      borderRadius: 1,
                      fontSize: "1.5rem",
                      "&:hover": {
                        bgcolor: "action.hover",
                        transform: "scale(1.2)",
                      },
                      transition: "all 0.1s ease",
                    }}
                  >
                    {emoji}
                  </Box>
                </Grid>
              ))}
            </Grid>
          </>
        )}

        {/* Category emojis or search results */}
        <Grid container>
          {filteredEmojis.map((emoji, index) => (
            <Grid item key={`${emoji}-${index}`}>
              <Box
                onClick={() => handleEmojiClick(emoji)}
                sx={{
                  cursor: "pointer",
                  p: 0.75,
                  borderRadius: 1,
                  fontSize: "1.5rem",
                  "&:hover": {
                    bgcolor: "action.hover",
                    transform: "scale(1.2)",
                  },
                  transition: "all 0.1s ease",
                }}
              >
                {emoji}
              </Box>
            </Grid>
          ))}
        </Grid>

        {filteredEmojis.length === 0 && (
          <Typography color="text.secondary" variant="body2" textAlign="center" sx={{ py: 4 }}>
            No emojis found
          </Typography>
        )}
      </Box>

      {/* Footer */}
      <Box
        sx={{
          px: 1.5,
          py: 0.5,
          borderTop: 1,
          borderColor: "divider",
          display: "flex",
          justifyContent: "flex-end",
        }}
      >
        <Typography variant="caption" color="text.secondary">
          Click to insert emoji
        </Typography>
      </Box>
    </Paper>
  );
};

export default EmojiPicker;
