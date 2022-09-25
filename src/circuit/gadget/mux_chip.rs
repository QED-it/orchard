use halo2_gadgets::ecc::chip::EccPoint;
use halo2_proofs::circuit::Value;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter},
    plonk::{self, Advice, Column, ConstraintSystem, Constraints, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

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
pub trait MuxInstructions<C: CurveAffine> {
    fn witness_switch(
        &self,
        layouter: impl Layouter<C::Base>,
        value: Value<bool>,
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

    /// If is_free_advice { advice = anything } else { advice = constant }
    fn conditional_advice(
        &self,
        layouter: impl Layouter<C::Base>,
        is_free_advice: &AssignedCell<C::Base, C::Base>,
        advice: &AssignedCell<C::Base, C::Base>,
        else_constant: &C::Base,
    ) -> Result<(), plonk::Error>;
}

impl MuxInstructions<pallas::Affine> for MuxChip {
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

    fn conditional_advice(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        is_free_advice: &AssignedCell<pallas::Base, pallas::Base>,
        advice: &AssignedCell<pallas::Base, pallas::Base>,
        else_constant: &pallas::Base,
    ) -> Result<(), plonk::Error> {
        layouter.assign_region(
            || "conditional advice",
            |mut region| {
                // Enable the multiplexer gate.
                self.config.q_mux.enable(&mut region, 0)?;

                // Copy the switch.
                is_free_advice.copy_advice(|| "copy switch", &mut region, self.config.switch, 0)?;

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
