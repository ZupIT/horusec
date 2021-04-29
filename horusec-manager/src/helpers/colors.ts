const generateRandomColor = (): string => {
  const x = Math.floor(Math.random() * 256);
  const y = Math.floor(Math.random() * 256);
  const z = Math.floor(Math.random() * 256);
  return `rgba(${x}, ${y}, ${z}, 0.55)`;
};

export { generateRandomColor };
