/* 
Copyright (C) 2011 by Scott Brooks
Copyright (C) 2011 by Alan De Smet

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

static const value_string directionnames[] = {
    {0, "-Y"},
    {1, "+Y"},
    {2, "-Z"},
    {3, "+Z"},
    {4, "-X"},
    {5, "+X"},
    {0, NULL}
};

static const value_string animations[] = {
    {0, "None"},
    {1, "Swing arm"},
    {2, "Take damage"},
    {104, "Crouch"},
    {105, "Stand"},
    {0, NULL}
};

static const value_string dimensions[] = {
    {0, "Normal World"},
    {-1, "The Nether"},
    {0, NULL}
};

static const value_string mobtypes[] = {
    {50, "Creeper"},
    {51, "Skeleton"},
    {52, "Spider"},
    {53, "GiantZombie"},
    {54, "Zombie"},
    {55, "Slime"},
    {56, "Ghast"},
    {57, "ZombiePigman"},
    {90, "Pig"},
    {91, "Sheep"},
    {92, "Cow"},
    {93, "Chicken"},
    {94, "Squid"},
    {95, "Wolf"},
    {0,  NULL}
};

static const value_string itemtypes[] = {
    {0x00, "Air"},
    {0x01, "Stone"},
    {0x02, "Grass"},
    {0x03, "Dirt"},
    {0x04, "Cobblestone"},
    {0x05, "Wooden Plank"},
    {0x06, "Sapling"},
    {0x07, "Bedrock"},
    {0x08, "Water"},
    {0x09, "Stationary Water"},
    {0x0A, "Lava"},
    {0x0B, "Stationary Lava"},
    {0x0C, "Sand"},    
    {0x0D, "Gravel"},
    {0x0E, "Gold Ore"},
    {0x0F, "Iron Ore"},    
    {0x10, "Coal Ore"},
    {0x11, "Wood"},
    {0x12, "Leaves"},
    {0x13, "Sponge"},
    {0x14, "Glass"},
    {0x15, "LapisLazuliOre"},
    {0x16, "LapisLazuliBlock"},
    {0x17, "Dispenser"},
    {0x18, "Sandstone"},
    {0x19, "NoteBlock"},
    {0x20, "DeadShrub"},
    {0x23, "Wool"},
    {0x25, "YellowFlower"},
    {0x26, "RedRose"},
    {0x27, "BrownMushroom"},
    {0x28, "RedMushroom"},
    {0x29, "GoldBlock"},
    {0x30, "MossStone"},
    {0x31, "Obsidian"},
    {0x32, "Torch"},
    {0x33, "Fire"},
    {0x34, "MonsterSpawner"},
    {0x35, "WoodenStairs"},
    {0x36, "Chest"},
    {0x37, "RedstoneWire_placed"},
    {0x38, "DiamondOre"},
    {0x39, "DiamondBlock"},
    {0x40, "WoodenDoor_placed"},
    {0x41, "Ladder"},
    {0x42, "MinecartTracks"},
    {0x43, "CobblestoneStairs"},
    {0x44, "WallSign_placed"},
    {0x45, "Lever"},
    {0x46, "StonePressurePlate"},
    {0x47, "IronDoor_placed"},
    {0x48, "WoodenPressurePlate"},
    {0x49, "RedstoneOre"},
    {0x50, "SnowBlock"},
    {0x51, "Cactus"},
    {0x52, "Clay"},
    {0x53, "SugarCane_placed"},
    {0x54, "Jukebox"},
    {0x55, "Fence"},
    {0x56, "Pumpkin"},
    {0x57, "Netherrack"},
    {0x58, "SoulSand"},
    {0x59, "Glowstone"},
    {0x60, "Trapdoor"},
    {0x100, "IronShovel"},
    {0x101, "IronPickaxe"},
    {0x102, "IronAxe"},
    {0x103, "FlintAndSteel"},
    {0x104, "Apple"},
    {0x105, "Bow"},
    {0x106, "Arrow"},
    {0x107, "Coal"},
    {0x108, "Diamond"},
    {0x109, "IronIngot"},
    {0x110, "StoneSword"},
    {0x111, "StoneShovel"},
    {0x112, "StonePickaxe"},
    {0x113, "StoneAxe"},
    {0x114, "DiamondSword"},
    {0x115, "DiamondShovel"},
    {0x116, "DiamondPickaxe"},
    {0x117, "DiamondAxe"},
    {0x118, "Stick"},
    {0x119, "Bowl"},
    {0x120, "Feather"},
    {0x121, "Gunpowder"},
    {0x122, "WoodenHoe"},
    {0x123, "StoneHoe"},
    {0x124, "IronHoe"},
    {0x125, "DiamondHoe"},
    {0x126, "GoldHoe"},
    {0x127, "Seeds"},
    {0x128, "Wheat"},
    {0x129, "Bread"},
    {0x130, "ChainmailLeggings"},
    {0x131, "ChainmailBoots"},
    {0x132, "IronHelmet"},
    {0x133, "IronChestplate"},
    {0x134, "IronLeggings"},
    {0x135, "IronBoots"},
    {0x136, "DiamondHelmet"},
    {0x137, "DiamondChestplate"},
    {0x138, "DiamondLeggings"},
    {0x139, "DiamondBoots"},
    {0x140, "CookedPorkchop"},
    {0x141, "Painting"},
    {0x142, "GoldenApple"},
    {0x143, "Sign"},
    {0x144, "WoodenDoor"},
    {0x145, "Bucket"},
    {0x146, "WaterBucket"},
    {0x147, "LavaBucket"},
    {0x148, "Minecart"},
    {0x149, "Saddle"},
    {0x150, "ClayBrick"},
    {0x151, "ClayBall"},
    {0x152, "SugarCane"},
    {0x153, "Paper"},
    {0x154, "Book"},
    {0x155, "Slimeball"},
    {0x156, "StorageMinecart"},
    {0x157, "PoweredMinecart"},
    {0x158, "Egg"},
    {0x159, "Compass"},
    {0x160, "Bone"},
    {0x161, "Sugar"},
    {0x162, "Cake"},
    {0x163, "Bed"},
    {0x164, "RedstoneRepeater"},
    {0,  NULL}
};
