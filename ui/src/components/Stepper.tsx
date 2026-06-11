interface StepperProps {
  steps: string[];
  current: number; // index of the active step
}

export default function Stepper({ steps, current }: StepperProps) {
  return (
    <div className="stepper">
      {steps.map((label, i) => (
        <div
          key={label}
          className={`step ${i < current ? 'done' : ''} ${i === current ? 'active' : ''}`}
        >
          <span className="step-num">{i < current ? '✓' : i + 1}</span>
          <span className="step-label">{label}</span>
          {i < steps.length - 1 && <span className="step-line" />}
        </div>
      ))}
    </div>
  );
}
