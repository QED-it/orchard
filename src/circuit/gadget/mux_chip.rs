use ff::Field;
use halo2_gadgets::ecc::chip::EccPoint;
use halo2_proofs::circuit::Value;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter},
    plonk::{self, Advice, Column, ConstraintSystem, Constraints, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

use crate::circuit::gadget::AddInstruction;

#[derive(Clone, Debug)]
pub(in crate::circuit) struct MuxConfig {
    q_mux: Selector,
    switch: Column<Advice>,
    left: Column<Advice>,
    right: Column<Advice>,
    out: Column<Advice>,
}

/// A chip implementing a multiplexer on a single row.
///
/// out = if (switch == 0) { left } else { right }
///
/// Switch must be constrained to {0, 1} separately.
pub(in crate::circuit) struct MuxChip {
    config: MuxConfig,
}

impl Chip<pallas::Base> for MuxChip {
    type Config = MuxConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl MuxChip {
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        switch: Column<Advice>,
        left: Column<Advice>,
        right: Column<Advice>,
        out: Column<Advice>,
    ) -> MuxConfig {
        let q_mux = meta.selector();

        meta.create_gate("Field element multiplexer", |meta| {
            let q_mux = meta.query_selector(q_mux);
            let switch = meta.query_advice(switch, Rotation::cur());
            let left = meta.query_advice(left, Rotation::cur());
            let right = meta.query_advice(right, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let not_switch = one - switch.clone();
            let should_be_zero = not_switch * left + switch * right - out;

            Constraints::with_selector(q_mux, Some(should_be_zero))
        });

        // TODO: is enable equality or enable constant needed?

        MuxConfig {
            q_mux,
            switch,
            left,
            right,
            out,
        }
    }

    pub(in crate::circuit) fn construct(config: MuxConfig) -> Self {
        Self { config }
    }
}

// TODO: simplify or generalize this API.
pub(crate) trait MuxInstructions<C: CurveAffine> {
    /// Witness a boolean switch value.
    fn witness_switch(
        &self,
        layouter: impl Layouter<C::Base>,
        value: Value<bool>,
    ) -> Result<AssignedCell<C::Base, C::Base>, plonk::Error>;

    /// Witness a value != 0
    fn witness_non_zero(
        &self,
        layouter: impl Layouter<C::Base>,
        value: Value<C::Base>,
    ) -> Result<AssignedCell<C::Base, C::Base>, plonk::Error>;

    fn mux(
        &self,
        layouter: impl Layouter<C::Base>,
        switch: &AssignedCell<C::Base, C::Base>,
        left: &AssignedCell<C::Base, C::Base>,
        right: &AssignedCell<C::Base, C::Base>,
    ) -> Result<AssignedCell<C::Base, C::Base>, plonk::Error>;

    fn mux_const(
        &self,
        layouter: impl Layouter<C::Base>,
        switch: &AssignedCell<C::Base, C::Base>,
        left: &C::Base,
        right: &AssignedCell<C::Base, C::Base>,
    ) -> Result<AssignedCell<C::Base, C::Base>, plonk::Error>;

    fn mux_point(
        &self,
        layouter: impl Layouter<pallas::Base>,
        switch: &AssignedCell<pallas::Base, pallas::Base>,
        left: &EccPoint,
        right: &EccPoint,
    ) -> Result<EccPoint, plonk::Error>;

    /// If is_any_value { advice = any value } else { advice = constant }
    /// Note that "any value" might equal the constant anyway.
    fn constant_or_any_value(
        &self,
        layouter: impl Layouter<C::Base>,
        is_any_value: &AssignedCell<C::Base, C::Base>,
        advice: &AssignedCell<C::Base, C::Base>,
        constant: &C::Base,
    ) -> Result<(), plonk::Error>;

    /// If is_different { advice != constant } else { advice == constant }
    fn constant_or_different(
        &self,
        layouter: impl Layouter<C::Base>,
        add_chip: impl AddInstruction<C::Base>,
        is_different: &AssignedCell<C::Base, C::Base>,
        advice: &AssignedCell<C::Base, C::Base>,
        constant: &C::Base,
    ) -> Result<(), plonk::Error>;
}

impl MuxInstructions<pallas::Affine> for MuxChip {
    /// Witness a boolean switch value.
    // TODO: this could return a wrapper type for usage safety.
    // TODO: this could use constant-time Choice instead of bool.
    fn witness_switch(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        value: Value<bool>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
        layouter.assign_region(
            || "witness switch",
            |mut region| {
                // This is a boolean constraint implemented with the mux gate.
                // Set left=switch, right=0, output=0, giving:
                //     (1 - switch) * switch == 0

                // Enable the multiplexer gate.
                self.config.q_mux.enable(&mut region, 0)?;

                let switch = region.assign_advice(
                    || "load switch",
                    self.config.switch,
                    0,
                    || value.map(pallas::Base::from),
                )?;

                // Copy the switch into the left input.
                switch.copy_advice(|| "copy switch", &mut region, self.config.left, 0)?;

                // Force the right input and the output to zero.
                region.assign_advice_from_constant(
                    || "null right",
                    self.config.right,
                    0,
                    pallas::Base::zero(),
                )?;
                region.assign_advice_from_constant(
                    || "null output",
                    self.config.out,
                    0,
                    pallas::Base::zero(),
                )?;

                Ok(switch)
            },
        )
    }

    /// Witness a value != 0
    fn witness_non_zero(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        value: Value<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
        layouter.assign_region(
            || "witness_non_zero",
            |mut region| {
                // This is a non-zero constraint implemented with the mux gate.
                // Set switch=value, right=1/value, left=0, output=1, giving:
                //     value * (1/value) == 1

                // Enable the multiplexer gate.
                self.config.q_mux.enable(&mut region, 0)?;

                let cell =
                    region.assign_advice(|| "witness value", self.config.switch, 0, || value)?;

                region.assign_advice(
                    || "witness 1/value",
                    self.config.right,
                    0,
                    || {
                        value.map(|v| {
                            let inverse = v.invert().unwrap();
                            inverse
                        })
                    },
                )?;

                // Set the "left" and "output" constants.
                region.assign_advice_from_constant(
                    || "left=0",
                    self.config.left,
                    0,
                    pallas::Base::zero(),
                )?;
                region.assign_advice_from_constant(
                    || "output=1",
                    self.config.out,
                    0,
                    pallas::Base::one(),
                )?;

                Ok(cell)
            },
        )
    }

    fn mux(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        switch: &AssignedCell<pallas::Base, pallas::Base>,
        left: &AssignedCell<pallas::Base, pallas::Base>,
        right: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
        layouter.assign_region(
            || "mux",
            |mut region| {
                // Enable the multiplexer gate.
                self.config.q_mux.enable(&mut region, 0)?;

                // Copy the inputs into the multiplexer row.
                switch.copy_advice(|| "copy switch", &mut region, self.config.switch, 0)?;
                left.copy_advice(|| "copy left", &mut region, self.config.left, 0)?;
                right.copy_advice(|| "copy right", &mut region, self.config.right, 0)?;

                // Assign the output value into the multiplexer row.
                let out_val = compute_mux(switch.value(), left.value(), right.value());

                region.assign_advice(|| "out", self.config.out, 0, || out_val)
            },
        )
    }

    fn mux_const(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        switch: &AssignedCell<pallas::Base, pallas::Base>,
        left: &pallas::Base,
        right: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
        layouter.assign_region(
            || "mux",
            |mut region| {
                // Enable the multiplexer gate.
                self.config.q_mux.enable(&mut region, 0)?;

                // Copy the inputs into the multiplexer row.
                switch.copy_advice(|| "copy switch", &mut region, self.config.switch, 0)?;

                region.assign_advice_from_constant(
                    || "constant left",
                    self.config.left,
                    0,
                    *left,
                )?;

                right.copy_advice(|| "copy right", &mut region, self.config.right, 0)?;

                // Assign the output value into the multiplexer row.
                let out_val = compute_mux(switch.value(), Value::known(left), right.value());

                region.assign_advice(|| "out", self.config.out, 0, || out_val)
            },
        )
    }

    fn mux_point(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        switch: &AssignedCell<pallas::Base, pallas::Base>,
        left: &EccPoint,
        right: &EccPoint,
    ) -> Result<EccPoint, plonk::Error> {
        let x = self.mux(
            layouter.namespace(|| "mux x"),
            switch,
            &left.x(),
            &right.x(),
        )?;
        let y = self.mux(
            layouter.namespace(|| "mux y"),
            switch,
            &left.y(),
            &right.y(),
        )?;

        Ok(EccPoint::from_coordinates_unchecked(x.into(), y.into()))
    }

    /// If is_any_value { advice = any value } else { advice = constant }
    /// Note that "any value" might equal the constant anyway.
    fn constant_or_any_value(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        is_any_value: &AssignedCell<pallas::Base, pallas::Base>,
        advice: &AssignedCell<pallas::Base, pallas::Base>,
        else_constant: &pallas::Base,
    ) -> Result<(), plonk::Error> {
        layouter.assign_region(
            || "equal_or_anything",
            |mut region| {
                // Enable the multiplexer gate.
                self.config.q_mux.enable(&mut region, 0)?;

                // Copy the switch.
                is_any_value.copy_advice(|| "copy switch", &mut region, self.config.switch, 0)?;

                // Copy the advice into the left input.
                // When the switch is off, it must equal the constant output.
                // When the switch is on, it is ignored so its value is freely chosen.
                advice.copy_advice(|| "copy advice", &mut region, self.config.left, 0)?;

                // The right witness just satisfies the gate when the switch is on.
                region.assign_advice(
                    || "witness right",
                    self.config.right,
                    0,
                    || Value::known(*else_constant),
                )?;

                // Force a constant output.
                region.assign_advice_from_constant(
                    || "constant output",
                    self.config.out,
                    0,
                    *else_constant,
                )?;

                Ok(())
            },
        )
    }

    /// If is_different { advice != constant } else { advice == constant }
    fn constant_or_different(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        add_chip: impl AddInstruction<pallas::Base>,
        is_different: &AssignedCell<pallas::Base, pallas::Base>,
        advice: &AssignedCell<pallas::Base, pallas::Base>,
        constant: &pallas::Base,
    ) -> Result<(), plonk::Error> {
        // Witness the difference between the advice and the constant.
        let non_zero_value =
            advice
                .value()
                .zip(is_different.value())
                .map(|(value, is_different)| {
                    let difference = constant - value;

                    if difference.is_zero_vartime() {
                        assert!(is_different.is_zero_vartime(), "expected equal values");
                        // If the values are equal, use any non-zero value to be ignored.
                        pallas::Base::one()
                    } else {
                        assert!(!is_different.is_zero_vartime(), "expected non-equal values");
                        difference
                    }
                });
        let non_zero =
            self.witness_non_zero(layouter.namespace(|| "non-zero difference"), non_zero_value)?;

        // Prepare a cell that is definitely different than the advice cell.
        let different_than_advice =
            add_chip.add(layouter.namespace(|| "different cell"), &advice, &non_zero)?;

        // Prepare a cell whose value equals the given constant.
        let advice_or_different = self.mux(
            layouter.namespace(|| "advice or different"),
            is_different,
            &advice,                // switch == 0, constant == advice
            &different_than_advice, // switch == 1, constant != advice
        )?;

        // Constrain the above cell to the given constant.
        layouter.assign_region(
            || "advice_or_different == constant",
            |mut region| region.constrain_constant(advice_or_different.cell(), constant),
        )?;
        Ok(())
    }
}

fn compute_mux(
    switch: Value<&pallas::Base>,
    left: Value<&pallas::Base>,
    right: Value<&pallas::Base>,
) -> Value<pallas::Base> {
    let one = Value::known(pallas::Base::one());
    let not_switch = one - switch;
    not_switch * left + switch * right
}
