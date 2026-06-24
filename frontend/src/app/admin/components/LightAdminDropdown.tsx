import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, Check } from "lucide-react";

export interface DropdownOption {
    value: string;
    label: string;
    icon?: React.ReactNode;
    disabled?: boolean;
}

interface LightAdminDropdownProps {
    value: string;
    options: DropdownOption[];
    onChange: (value: string) => void;
    placeholder?: string;
    className?: string;
}

export function LightAdminDropdown({
    value,
    options,
    onChange,
    placeholder = "Select an option",
    className = ""
}: LightAdminDropdownProps) {
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);

    const selectedOption = options.find(opt => opt.value === value);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };

        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "Enter" || e.key === " ") {
            setIsOpen(!isOpen);
            e.preventDefault();
        } else if (e.key === "Escape") {
            setIsOpen(false);
        }
    };

    return (
        <div className={`relative ${className}`} ref={dropdownRef}>
            <button
                type="button"
                onClick={() => setIsOpen(!isOpen)}
                onKeyDown={handleKeyDown}
                className={`
                    relative w-full h-[40px] px-[14px] flex items-center justify-between gap-3
                    bg-white border rounded-xl shadow-sm
                    transition-all duration-200 cursor-pointer overflow-hidden group
                    focus:outline-none focus:border-[#00A884] focus:ring-[3px] focus:ring-[#10B981]/15
                    ${isOpen ? "border-[#00A884] shadow-md" : "border-[#E6DDD2] hover:border-[#10B981] hover:shadow-md hover:-translate-y-[1px]"}
                `}
                aria-haspopup="listbox"
                aria-expanded={isOpen}
            >
                {/* Shiny hover effect */}
                <div className="absolute inset-0 w-1/2 h-full bg-gradient-to-r from-transparent via-white/40 to-transparent -skew-x-12 -translate-x-full group-hover:translate-x-[300%] transition-transform duration-1000 ease-out pointer-events-none" />

                <span className={`text-xs font-bold truncate ${selectedOption ? "text-[#1F2933]" : "text-[#7C6F64]"}`}>
                    {selectedOption ? selectedOption.label : placeholder}
                </span>
                
                <ChevronDown 
                    className={`w-4 h-4 text-[#7C6F64] transition-transform duration-200 ${isOpen ? "rotate-180 text-[#00A884]" : ""}`} 
                />
            </button>

            <AnimatePresence>
                {isOpen && (
                    <motion.div
                        initial={{ opacity: 0, y: -4, scale: 0.98 }}
                        animate={{ opacity: 1, y: 4, scale: 1 }}
                        exit={{ opacity: 0, y: -4, scale: 0.98 }}
                        transition={{ duration: 0.15, ease: "easeOut" }}
                        className="absolute z-50 w-full min-w-[160px] bg-white border border-[#E6DDD2] rounded-xl shadow-lg p-1.5 backdrop-blur-md"
                        role="listbox"
                    >
                        <div className="max-h-[240px] overflow-y-auto custom-scrollbar flex flex-col gap-0.5">
                            {options.map((option) => {
                                const isSelected = option.value === value;
                                return (
                                    <button
                                        key={option.value}
                                        type="button"
                                        disabled={option.disabled}
                                        onClick={() => {
                                            onChange(option.value);
                                            setIsOpen(false);
                                        }}
                                        className={`
                                            w-full flex items-center justify-between px-3 py-2.5 rounded-[10px] text-xs transition-all duration-150
                                            ${option.disabled ? "opacity-45 cursor-not-allowed" : "cursor-pointer"}
                                            ${isSelected 
                                                ? "bg-[#DCFCE7] text-[#047857] font-bold" 
                                                : "text-[#1F2933] hover:bg-[#F0FDF4] hover:text-[#00A884] font-medium"
                                            }
                                        `}
                                        role="option"
                                        aria-selected={isSelected}
                                    >
                                        <div className="flex items-center gap-2 truncate">
                                            {option.icon && <span className="shrink-0">{option.icon}</span>}
                                            <span className="truncate">{option.label}</span>
                                        </div>
                                        {isSelected && <Check className="w-3.5 h-3.5 shrink-0 text-[#047857]" />}
                                    </button>
                                );
                            })}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
